"""Tests for capture upload over MCP.

The feature exists for deployments where the server and the agent do not share a
filesystem, so the properties worth pinning are the ones that make that safe: a
handle is unguessable and expiring, content is checked before it is stored, a
partial transfer cannot be analyzed, and the handle resolves for *every* existing
tool without that tool knowing about uploads.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from pathlib import Path
from typing import Any

import pytest
from conftest import MockTSharkClient, call_tool_text

from wireshark_mcp.mcp_app import WiresharkMCP
from wireshark_mcp.tools.uploads import register_upload_tools
from wireshark_mcp.uploads import (
    DEFAULT_UPLOAD_DIR_NAME,
    MAX_UPLOAD_BYTES_ENV,
    UPLOAD_DIR_ENV,
    UPLOAD_TTL_ENV,
    DisabledUploadStore,
    UploadError,
    UploadStore,
    create_upload_store,
    detect_capture_format,
    resolve_upload_dir,
)

PCAP_HEADER = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 12
PCAPNG_HEADER = b"\x0a\x0d\x0d\x0a" + b"\x00" * 20


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


@pytest.fixture
def store(tmp_path: Path) -> UploadStore:
    directory = tmp_path / "uploads"
    directory.mkdir()
    return UploadStore(directory, max_bytes=4096, ttl_seconds=3600)


@pytest.fixture
def upload_mcp(store: UploadStore, mock_client: MockTSharkClient) -> WiresharkMCP:
    mcp = WiresharkMCP("test", upload_store=store)
    register_upload_tools(mcp, mock_client, store)
    return mcp


# ── Format detection ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("head", "expected"),
    [
        (b"\xd4\xc3\xb2\xa1", "pcap"),  # little-endian microsecond
        (b"\xa1\xb2\xc3\xd4", "pcap"),  # big-endian microsecond
        (b"\x4d\x3c\xb2\xa1", "pcap"),  # little-endian nanosecond
        (b"\xa1\xb2\x3c\x4d", "pcap"),  # big-endian nanosecond
        (b"\x0a\x0d\x0d\x0a", "pcapng"),
        (b"PK\x03\x04", None),  # zip
        (b"\x7fELF", None),
        (b"", None),
    ],
)
def test_capture_format_detection(head: bytes, expected: str | None) -> None:
    assert detect_capture_format(head) == expected


# ── Store behaviour ─────────────────────────────────────────────────────


def test_one_shot_upload_returns_a_resolvable_handle(store: UploadStore) -> None:
    record = store.write(_b64(PCAP_HEADER), filename="demo.pcap")

    assert record["complete"] is True
    assert record["format"] == "pcap"
    assert record["size"] == len(PCAP_HEADER)
    assert store.resolve(record["handle"]).read_bytes() == PCAP_HEADER


def test_handle_is_unguessable_and_scheme_qualified(store: UploadStore) -> None:
    """Possession of the handle is the only authorization, so it must be random."""
    handles = {store.write(_b64(PCAP_HEADER))["handle"] for _ in range(5)}

    assert len(handles) == 5
    for handle in handles:
        assert handle.startswith("upload://")
        assert len(handle.removeprefix("upload://")) == 32
        int(handle.removeprefix("upload://"), 16)  # raises if not hex


def test_non_capture_content_is_rejected_and_not_stored(store: UploadStore) -> None:
    with pytest.raises(UploadError, match="not a pcap or pcapng"):
        store.write(_b64(b"#!/bin/sh\nrm -rf /\n"))

    assert list(store.directory.glob("*")) == []


def test_upload_over_the_size_limit_is_rejected(store: UploadStore) -> None:
    oversized = PCAP_HEADER + b"\x00" * 5000

    with pytest.raises(UploadError, match="over the 4096 byte limit"):
        store.write(_b64(oversized))

    assert list(store.directory.glob("*")) == []


def test_invalid_base64_is_reported_as_such(store: UploadStore) -> None:
    with pytest.raises(UploadError, match="not valid base64"):
        store.write("not!base64!")


def test_base64_may_be_line_wrapped(store: UploadStore) -> None:
    """Clients that wrap long base64 must not be rejected over whitespace."""
    payload = _b64(PCAP_HEADER + b"\x00" * 200)
    wrapped = "\n".join(payload[i : i + 40] for i in range(0, len(payload), 40))

    assert store.write(wrapped)["complete"] is True


# ── Chunked transfer ────────────────────────────────────────────────────


def test_chunked_upload_assembles_in_order(store: UploadStore) -> None:
    body = bytes(range(256)) * 4
    first = store.write(_b64(PCAP_HEADER), filename="big.pcap", more_chunks=True)
    assert first["complete"] is False

    store.write(_b64(body[:512]), handle=first["handle"], more_chunks=True)
    final = store.write(_b64(body[512:]), handle=first["handle"])

    assert final["complete"] is True
    assert final["handle"] == first["handle"]
    assert store.resolve(final["handle"]).read_bytes() == PCAP_HEADER + body


def test_incomplete_upload_cannot_be_resolved(store: UploadStore) -> None:
    """A half-transferred capture must never reach tshark as if it were whole."""
    pending = store.write(_b64(PCAP_HEADER), more_chunks=True)

    with pytest.raises(UploadError, match="still incomplete"):
        store.resolve(pending["handle"])


def test_chunks_may_not_exceed_the_limit_and_the_partial_is_discarded(store: UploadStore) -> None:
    pending = store.write(_b64(PCAP_HEADER), more_chunks=True)

    with pytest.raises(UploadError, match="over the 4096 byte limit"):
        store.write(_b64(b"\x00" * 5000), handle=pending["handle"])

    with pytest.raises(UploadError, match="Unknown or expired"):
        store.resolve(pending["handle"])


def test_appending_to_a_finished_upload_is_refused(store: UploadStore) -> None:
    record = store.write(_b64(PCAP_HEADER))

    with pytest.raises(UploadError, match="already complete"):
        store.write(_b64(b"\x00" * 8), handle=record["handle"])


def test_a_chunked_upload_that_never_becomes_a_capture_is_rejected(store: UploadStore) -> None:
    """The magic check is deferred for chunks, so it must still run at finalize."""
    pending = store.write(_b64(b"not-a-capture"), more_chunks=True)

    with pytest.raises(UploadError, match="not a pcap or pcapng"):
        store.write(_b64(b"-either"), handle=pending["handle"])

    assert list(store.directory.glob("*")) == []


def test_malformed_handle_is_rejected(store: UploadStore) -> None:
    for bad in ("upload://xyz", "upload://" + "g" * 32, "/etc/passwd", "upload://"):
        with pytest.raises(UploadError):
            store.resolve(bad)


# ── Lifecycle ───────────────────────────────────────────────────────────


def test_uploads_expire_and_are_swept(tmp_path: Path) -> None:
    directory = tmp_path / "uploads"
    directory.mkdir()
    store = UploadStore(directory, max_bytes=4096, ttl_seconds=1)
    record = store.write(_b64(PCAP_HEADER))

    time.sleep(1.1)
    assert store.sweep() == 1

    with pytest.raises(UploadError, match="Unknown or expired"):
        store.resolve(record["handle"])
    assert list(directory.glob("*")) == []


def test_appending_does_not_extend_the_lease(tmp_path: Path) -> None:
    """Age is measured from creation, so a slow transfer cannot hold disk forever."""
    directory = tmp_path / "uploads"
    directory.mkdir()
    store = UploadStore(directory, max_bytes=4096, ttl_seconds=1)
    pending = store.write(_b64(PCAP_HEADER), more_chunks=True)

    time.sleep(1.1)
    with pytest.raises(UploadError, match="Unknown or expired"):
        store.write(_b64(b"\x00" * 8), handle=pending["handle"])


def test_explicit_delete_removes_the_files(store: UploadStore) -> None:
    record = store.write(_b64(PCAP_HEADER))

    assert store.delete(record["handle"]) is True
    assert store.delete(record["handle"]) is False
    assert list(store.directory.glob("*")) == []


def test_listing_reports_live_records_with_remaining_lifetime(store: UploadStore) -> None:
    store.write(_b64(PCAP_HEADER), filename="a.pcap")
    store.write(_b64(PCAPNG_HEADER), filename="b.pcapng")

    records = store.list_uploads()

    assert [r["filename"] for r in records] == ["a.pcap", "b.pcapng"]
    assert all(0 < r["expires_in_seconds"] <= 3600 for r in records)


def test_public_record_never_exposes_the_server_path(store: UploadStore) -> None:
    """The model's transcript should not learn the server's filesystem layout."""
    record = store.write(_b64(PCAP_HEADER), filename="demo.pcap")

    serialized = json.dumps(record)
    assert str(store.directory) not in serialized
    assert "path" not in record


def test_filename_cannot_smuggle_a_directory_component(store: UploadStore) -> None:
    record = store.write(_b64(PCAP_HEADER), filename="../../etc/passwd")

    assert "/" not in record["filename"]
    assert ".." not in record["filename"]
    assert store.resolve(record["handle"]).parent == store.directory


def test_a_tampered_sidecar_cannot_delete_outside_the_sandbox(store: UploadStore, tmp_path: Path) -> None:
    """`stored_name` comes off disk, so deletion must re-anchor it to the sandbox."""
    victim = tmp_path / "precious.txt"
    victim.write_text("keep me", encoding="utf-8")
    record = store.write(_b64(PCAP_HEADER))
    upload_id = record["handle"].removeprefix("upload://")

    meta_path = store.directory / f"{upload_id}.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["stored_name"] = "../precious.txt"
    meta_path.write_text(json.dumps(meta), encoding="utf-8")

    store.delete(record["handle"])

    assert victim.exists()


# ── Handle resolution across the whole tool surface ─────────────────────


def test_handles_resolve_for_tools_that_know_nothing_about_uploads(
    store: UploadStore, mock_client: MockTSharkClient
) -> None:
    """The point of the choke point: no existing tool signature changed."""
    from wireshark_mcp.tools.extract import register_extract_tools

    record = store.write(_b64(PCAP_HEADER))
    mcp = WiresharkMCP("test", upload_store=store)
    register_extract_tools(mcp, mock_client)

    result = json.loads(_run(call_tool_text(mcp, "wireshark_read_packets", {"pcap_file": record["handle"]})))

    assert result["success"] is True
    assert str(store.resolve(record["handle"])) in result["data"]


def test_handles_resolve_inside_comma_separated_arguments(store: UploadStore, mock_client: MockTSharkClient) -> None:
    first = store.write(_b64(PCAP_HEADER))
    second = store.write(_b64(PCAPNG_HEADER))
    mcp = WiresharkMCP("test", upload_store=store)

    resolved = mcp._resolve_upload_handles(
        "wireshark_merge_pcaps",
        {"input_files": f"{first['handle']},{second['handle']}", "output_file": "/tmp/out.pcap"},
    )

    assert resolved["input_files"] == f"{store.resolve(first['handle'])},{store.resolve(second['handle'])}"


def test_output_parameters_are_never_resolved(store: UploadStore) -> None:
    """A handle in an output path would let a writer overwrite a stored upload."""
    record = store.write(_b64(PCAP_HEADER))
    mcp = WiresharkMCP("test", upload_store=store)

    resolved = mcp._resolve_upload_handles(
        "wireshark_filter_save",
        {"input_file": record["handle"], "output_file": record["handle"]},
    )

    assert resolved["output_file"] == record["handle"]
    assert resolved["input_file"] == str(store.resolve(record["handle"]))


def test_the_upload_tools_own_handle_argument_is_left_alone(store: UploadStore) -> None:
    record = store.write(_b64(PCAP_HEADER))
    mcp = WiresharkMCP("test", upload_store=store)

    resolved = mcp._resolve_upload_handles("wireshark_delete_upload", {"upload_handle": record["handle"]})

    assert resolved["upload_handle"] == record["handle"]


def test_an_unknown_handle_fails_the_call_with_a_tool_envelope(
    store: UploadStore, mock_client: MockTSharkClient
) -> None:
    from wireshark_mcp.tools.extract import register_extract_tools

    mcp = WiresharkMCP("test", upload_store=store)
    register_extract_tools(mcp, mock_client)

    result = json.loads(_run(call_tool_text(mcp, "wireshark_read_packets", {"pcap_file": "upload://" + "0" * 32})))

    assert result["success"] is False
    assert result["error"]["type"] == "FileNotFound"


def test_arguments_without_a_handle_are_passed_through_untouched(store: UploadStore) -> None:
    mcp = WiresharkMCP("test", upload_store=store)
    arguments = {"pcap_file": "/captures/demo.pcap", "limit": 10, "verbose": True}

    assert mcp._resolve_upload_handles("wireshark_read_packets", arguments) == arguments


# ── Tool layer ──────────────────────────────────────────────────────────


def test_upload_tool_round_trip(upload_mcp: WiresharkMCP, store: UploadStore) -> None:
    result = json.loads(
        _run(
            call_tool_text(
                upload_mcp,
                "wireshark_upload_capture",
                {"content_base64": _b64(PCAP_HEADER), "filename": "demo.pcap"},
            )
        )
    )

    assert result["success"] is True
    handle = result["data"]["handle"]

    listed = json.loads(_run(call_tool_text(upload_mcp, "wireshark_list_uploads", {})))
    assert listed["data"]["count"] == 1
    assert listed["data"]["uploads"][0]["handle"] == handle

    deleted = json.loads(_run(call_tool_text(upload_mcp, "wireshark_delete_upload", {"upload_handle": handle})))
    assert deleted["data"]["deleted"] is True
    assert store.list_uploads() == []


def test_upload_tool_reports_an_incomplete_chunked_transfer(upload_mcp: WiresharkMCP) -> None:
    result = json.loads(
        _run(
            call_tool_text(
                upload_mcp,
                "wireshark_upload_capture",
                {"content_base64": _b64(PCAP_HEADER), "more_chunks": True},
            )
        )
    )

    assert result["success"] is True
    assert result["data"]["complete"] is False
    assert result["warnings"]


def test_upload_tool_rejects_content_that_capinfos_cannot_read(
    store: UploadStore, mock_client: MockTSharkClient
) -> None:
    """Magic bytes alone are not proof; a capture the suite cannot open is dropped."""

    async def failing_get_file_info(pcap_file: str) -> str:
        return json.dumps({"success": False, "error": {"type": "ToolError", "message": "truncated file"}})

    mock_client.get_file_info = failing_get_file_info  # type: ignore[method-assign]
    mcp = WiresharkMCP("test", upload_store=store)
    register_upload_tools(mcp, mock_client, store)

    result = json.loads(_run(call_tool_text(mcp, "wireshark_upload_capture", {"content_base64": _b64(PCAP_HEADER)})))

    assert result["success"] is False
    assert "truncated file" in result["error"]["message"]
    assert store.list_uploads() == []


def test_deleting_an_unknown_handle_is_an_error(upload_mcp: WiresharkMCP) -> None:
    result = json.loads(
        _run(call_tool_text(upload_mcp, "wireshark_delete_upload", {"upload_handle": "upload://" + "a" * 32}))
    )

    assert result["success"] is False
    assert result["error"]["type"] == "FileNotFound"


# ── Disabled by default ─────────────────────────────────────────────────


def test_uploads_are_disabled_without_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(UPLOAD_DIR_ENV, raising=False)

    assert isinstance(create_upload_store(None), DisabledUploadStore)


def test_disabled_store_fails_closed_with_an_actionable_message(
    mock_client: MockTSharkClient,
) -> None:
    store = DisabledUploadStore()
    mcp = WiresharkMCP("test", upload_store=store)
    register_upload_tools(mcp, mock_client, store)

    result = json.loads(_run(call_tool_text(mcp, "wireshark_upload_capture", {"content_base64": _b64(PCAP_HEADER)})))

    assert result["success"] is False
    assert result["error"]["type"] == "PermissionDenied"
    assert UPLOAD_DIR_ENV in result["error"]["message"]


def test_disabled_store_refuses_to_resolve_a_handle(mock_client: MockTSharkClient) -> None:
    """A handle must not silently fall through to the filesystem when disabled."""
    from wireshark_mcp.tools.extract import register_extract_tools

    mcp = WiresharkMCP("test", upload_store=DisabledUploadStore())
    register_extract_tools(mcp, mock_client)

    result = json.loads(_run(call_tool_text(mcp, "wireshark_read_packets", {"pcap_file": "upload://" + "0" * 32})))

    assert result["success"] is False
    assert result["error"]["type"] == "PermissionDenied"


def test_upload_tools_are_registered_even_when_uploads_are_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The advertised surface must not depend on deployment configuration."""
    from wireshark_mcp.server import _build_server

    monkeypatch.delenv(UPLOAD_DIR_ENV, raising=False)
    monkeypatch.setenv("WIRESHARK_MCP_ALLOWED_DIRS", "")

    mcp = _build_server(host="127.0.0.1", port=8080, log_level="ERROR")
    names = {t.name for t in _run(mcp.list_tools())}

    assert {"wireshark_upload_capture", "wireshark_list_uploads", "wireshark_delete_upload"} <= names
    assert isinstance(mcp.upload_store, DisabledUploadStore)


# ── Configuration ───────────────────────────────────────────────────────


def test_explicit_upload_dir_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(UPLOAD_DIR_ENV, str(tmp_path / "explicit"))

    assert resolve_upload_dir(["/srv/pcaps"]) == tmp_path / "explicit"


def test_upload_dir_defaults_under_the_first_allowed_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(UPLOAD_DIR_ENV, raising=False)

    assert resolve_upload_dir(["/srv/pcaps", "/srv/results"]) == Path("/srv/pcaps") / DEFAULT_UPLOAD_DIR_NAME


def test_limits_are_configurable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(UPLOAD_DIR_ENV, str(tmp_path / "uploads"))
    monkeypatch.setenv(MAX_UPLOAD_BYTES_ENV, "2048")
    monkeypatch.setenv(UPLOAD_TTL_ENV, "60")

    store = create_upload_store(None)

    assert store.max_bytes == 2048
    assert store.ttl_seconds == 60


def test_nonsense_limits_fall_back_to_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(UPLOAD_DIR_ENV, str(tmp_path / "uploads"))
    monkeypatch.setenv(MAX_UPLOAD_BYTES_ENV, "not-a-number")
    monkeypatch.setenv(UPLOAD_TTL_ENV, "-5")

    store = create_upload_store(None)

    assert store.max_bytes == 100 * 1024 * 1024
    assert store.ttl_seconds == 3600


def test_an_upload_dir_outside_the_sandbox_joins_the_allowed_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Otherwise a resolved handle would fail the path check it just opted into."""
    from wireshark_mcp.server import _build_server

    captures = tmp_path / "captures"
    uploads = tmp_path / "elsewhere"
    captures.mkdir()
    monkeypatch.setenv("WIRESHARK_MCP_ALLOWED_DIRS", str(captures))
    monkeypatch.setenv(UPLOAD_DIR_ENV, str(uploads))

    mcp = _build_server(host="127.0.0.1", port=8080, log_level="ERROR")
    store = mcp.upload_store
    assert store is not None

    record = store.write(_b64(PCAP_HEADER))
    stored = store.resolve(record["handle"])

    from wireshark_mcp.tshark.client import WiresharkSuiteClient

    client = WiresharkSuiteClient(allowed_dirs=[str(captures), str(uploads)])
    assert client._validate_file(str(stored))["success"] is True


def test_upload_directory_is_private(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    if sys.platform == "win32":
        pytest.skip("POSIX permission bits")

    monkeypatch.setenv(UPLOAD_DIR_ENV, str(tmp_path / "uploads"))
    store = create_upload_store(None)

    assert (store.directory.stat().st_mode & 0o077) == 0


def test_the_upload_tool_name_list_cannot_drift(mock_client: MockTSharkClient) -> None:
    """`_UPLOAD_TOOL_NAMES` in mcp_app duplicates what tools/uploads.py registers.

    Renaming a tool without updating that set would silently start rewriting the
    upload tools' own `upload_handle` argument into a path, breaking append and
    delete. Pin the two together.
    """
    from wireshark_mcp.mcp_app import _UPLOAD_TOOL_NAMES

    mcp = WiresharkMCP("test", upload_store=DisabledUploadStore())
    register_upload_tools(mcp, mock_client, DisabledUploadStore())
    registered = {t.name for t in _run(mcp.list_tools())}

    assert registered == _UPLOAD_TOOL_NAMES
