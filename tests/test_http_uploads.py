"""Tests for the raw-body HTTP upload route and the store's streaming ingest.

This is the path large captures take — through an MCP gateway's passthrough,
usually via a short-lived upload URL — so what is worth pinning is that it
enforces exactly what the base64 tool enforces, answers each rejection with a
distinct status the gateway can relay, and never leaves a partial behind.
"""

from __future__ import annotations

import asyncio
import base64
import json
from typing import TYPE_CHECKING

import pytest
from starlette.testclient import TestClient

from wireshark_mcp.http_uploads import UPLOAD_ROUTE_PATH, register_upload_routes
from wireshark_mcp.mcp_app import WiresharkMCP
from wireshark_mcp.uploads import STREAM_BLOCK_BYTES, DisabledUploadStore, UploadError, UploadStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator
    from pathlib import Path

    from conftest import MockTSharkClient


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


PCAP_HEADER = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 12


def _app(store: UploadStore, client: MockTSharkClient) -> TestClient:
    from mcp.server.streamable_http import TransportSecuritySettings

    mcp = WiresharkMCP("test", upload_store=store)
    register_upload_routes(mcp, client, store)
    sec = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    return TestClient(mcp.streamable_http_app(transport_security=sec), base_url="http://127.0.0.1")


def _chunked(data: bytes, size: int = 1000) -> Iterator[bytes]:
    """A generator body, which the test client sends without Content-Length."""
    for i in range(0, len(data), size):
        yield data[i : i + size]


async def _aiter(parts: list[bytes]) -> AsyncIterator[bytes]:
    for part in parts:
        yield part


@pytest.fixture
def store(tmp_path: Path) -> UploadStore:
    directory = tmp_path / "uploads"
    directory.mkdir()
    return UploadStore(directory, max_bytes=4096, ttl_seconds=3600, max_total_bytes=8192)


@pytest.fixture
def http(store: UploadStore, mock_client: MockTSharkClient) -> Iterator[TestClient]:
    with _app(store, mock_client) as client:
        yield client


# ── The route ───────────────────────────────────────────────────────────


def test_raw_body_is_stored_and_returns_a_resolvable_handle(http: TestClient, store: UploadStore) -> None:
    body = PCAP_HEADER + b"\x01" * 500

    res = http.post(f"{UPLOAD_ROUTE_PATH}?filename=incident.pcap", content=body)

    assert res.status_code == 201
    record = res.json()["data"]
    assert record["complete"] is True
    assert record["format"] == "pcap"
    assert record["filename"] == "incident.pcap"
    assert record["size"] == len(body)
    assert store.resolve(record["handle"]).read_bytes() == body


def test_a_chunked_body_without_content_length_is_accepted(http: TestClient, store: UploadStore) -> None:
    body = PCAP_HEADER + bytes(range(256)) * 10

    res = http.post(UPLOAD_ROUTE_PATH, content=_chunked(body))

    assert res.status_code == 201
    assert store.resolve(res.json()["data"]["handle"]).read_bytes() == body


def test_response_never_contains_the_server_path(http: TestClient, store: UploadStore) -> None:
    res = http.post(UPLOAD_ROUTE_PATH, content=PCAP_HEADER)

    assert str(store.directory) not in res.text


def test_filename_is_sanitized(http: TestClient) -> None:
    res = http.post(UPLOAD_ROUTE_PATH, params={"filename": "../../etc/passwd"}, content=PCAP_HEADER)

    assert res.status_code == 201
    assert "/" not in res.json()["data"]["filename"]


def test_declared_oversize_is_rejected_before_anything_is_written(http: TestClient, store: UploadStore) -> None:
    res = http.post(UPLOAD_ROUTE_PATH, content=PCAP_HEADER + b"\x00" * 5000)

    assert res.status_code == 413
    assert res.json()["success"] is False
    assert list(store.directory.glob("*")) == []


def test_streamed_oversize_is_rejected_and_the_partial_removed(http: TestClient, store: UploadStore) -> None:
    """Without Content-Length the cap can only be enforced on the running total."""
    res = http.post(UPLOAD_ROUTE_PATH, content=_chunked(PCAP_HEADER + b"\x00" * 5000))

    assert res.status_code == 413
    assert list(store.directory.glob("*")) == []


def test_non_capture_is_rejected_with_415(http: TestClient, store: UploadStore) -> None:
    res = http.post(UPLOAD_ROUTE_PATH, content=b"PK\x03\x04 definitely a zip")

    assert res.status_code == 415
    assert list(store.directory.glob("*")) == []


def test_empty_body_is_rejected(http: TestClient, store: UploadStore) -> None:
    res = http.post(UPLOAD_ROUTE_PATH, content=b"")

    assert res.status_code == 400
    assert list(store.directory.glob("*")) == []


def test_capture_capinfos_cannot_read_is_rejected_with_422(store: UploadStore, mock_client: MockTSharkClient) -> None:
    async def failing_get_file_info(pcap_file: str) -> str:
        return json.dumps({"success": False, "error": {"type": "ToolError", "message": "truncated file"}})

    mock_client.get_file_info = failing_get_file_info  # type: ignore[method-assign]
    with _app(store, mock_client) as http:
        res = http.post(UPLOAD_ROUTE_PATH, content=PCAP_HEADER)

    assert res.status_code == 422
    assert "truncated file" in res.json()["error"]["message"]
    assert list(store.directory.glob("*")) == []


def test_quota_exhaustion_is_reported_as_507(http: TestClient, store: UploadStore) -> None:
    """Total quota is 8192 here; two 4000-byte uploads fit, a third does not."""
    body = PCAP_HEADER + b"\x00" * (4000 - len(PCAP_HEADER))
    assert http.post(UPLOAD_ROUTE_PATH, content=body).status_code == 201
    assert http.post(UPLOAD_ROUTE_PATH, content=body).status_code == 201

    res = http.post(UPLOAD_ROUTE_PATH, content=body)

    assert res.status_code == 507
    assert res.json()["error"]["type"] == "QuotaExceeded"
    assert len(store.list_uploads()) == 2


def test_quota_is_enforced_on_streamed_bodies_too(http: TestClient, store: UploadStore) -> None:
    body = PCAP_HEADER + b"\x00" * (4000 - len(PCAP_HEADER))
    http.post(UPLOAD_ROUTE_PATH, content=body)
    http.post(UPLOAD_ROUTE_PATH, content=body)

    res = http.post(UPLOAD_ROUTE_PATH, content=_chunked(body))

    assert res.status_code == 507
    assert len(list(store.directory.glob("*.part"))) == 0


def test_disabled_uploads_answer_403(mock_client: MockTSharkClient) -> None:
    with _app(DisabledUploadStore(), mock_client) as http:
        res = http.post(UPLOAD_ROUTE_PATH, content=PCAP_HEADER)

    assert res.status_code == 403
    assert res.json()["error"]["type"] == "PermissionDenied"


def test_the_route_adds_nothing_to_the_tool_list(store: UploadStore, mock_client: MockTSharkClient) -> None:
    """The prompt-prefix budget must not pay for an HTTP route."""
    mcp = WiresharkMCP("test", upload_store=store)
    register_upload_routes(mcp, mock_client, store)

    assert asyncio.run(mcp.list_tools()) == []


def test_the_route_is_registered_by_the_real_server(monkeypatch: pytest.MonkeyPatch) -> None:
    from wireshark_mcp.server import _build_server

    monkeypatch.delenv("WIRESHARK_MCP_UPLOAD_DIR", raising=False)
    monkeypatch.setenv("WIRESHARK_MCP_ALLOWED_DIRS", "")
    mcp = _build_server(host="127.0.0.1", port=8080, log_level="ERROR")

    paths = {getattr(route, "path", None) for route in mcp.streamable_http_app().routes}
    assert UPLOAD_ROUTE_PATH in paths


# ── Streaming ingest in the store ───────────────────────────────────────


def test_ingest_writes_in_blocks_across_many_small_chunks(tmp_path: Path) -> None:
    """Exercise the block buffer: more than one block, arriving in small reads."""
    store = UploadStore(tmp_path, max_bytes=4 * STREAM_BLOCK_BYTES, ttl_seconds=3600)
    body = PCAP_HEADER + b"\xab" * (STREAM_BLOCK_BYTES * 2 + 123)
    parts = [body[i : i + 65536] for i in range(0, len(body), 65536)]

    record = asyncio.run(store.ingest_stream(_aiter(parts), filename="big.pcap"))

    assert record["size"] == len(body)
    assert store.resolve(record["handle"]).read_bytes() == body


def test_ingest_removes_the_partial_when_the_client_goes_away(store: UploadStore) -> None:
    class Gone(Exception):
        pass

    async def disconnecting() -> AsyncIterator[bytes]:
        yield PCAP_HEADER
        raise Gone

    with pytest.raises(Gone):
        asyncio.run(store.ingest_stream(disconnecting()))

    assert list(store.directory.glob("*")) == []


def test_ingest_fails_cleanly_if_the_record_is_deleted_mid_transfer(tmp_path: Path) -> None:
    """A delete mid-stream must not leave an orphaned data file nothing sweeps."""
    store = UploadStore(tmp_path, max_bytes=4 * STREAM_BLOCK_BYTES, ttl_seconds=3600)

    async def deleting() -> AsyncIterator[bytes]:
        yield PCAP_HEADER + b"\x00" * STREAM_BLOCK_BYTES  # forces a first block write
        for meta in tmp_path.glob("*.json"):
            store.delete("upload://" + meta.stem)
        yield b"\x00" * STREAM_BLOCK_BYTES

    with pytest.raises(UploadError, match="expired or was deleted"):
        asyncio.run(store.ingest_stream(deleting()))

    assert list(tmp_path.glob("*")) == []


def test_disabled_store_refuses_to_ingest() -> None:
    with pytest.raises(UploadError) as info:
        asyncio.run(DisabledUploadStore().ingest_stream(_aiter([PCAP_HEADER])))

    assert info.value.status == 403


def test_appending_to_a_removed_record_never_recreates_its_data_file(tmp_path: Path) -> None:
    """Covers the race between a block's reservation and its write.

    `_reserve` catches a delete that lands first; this guards the window after
    it. Recreating the file there would leave data no sidecar points at, which
    the sweep — keyed on sidecars — would never reclaim.
    """
    store = UploadStore(tmp_path, max_bytes=4096, ttl_seconds=3600)
    pending = store.write(_b64(PCAP_HEADER), more_chunks=True)
    upload_id = pending["handle"].removeprefix("upload://")
    store.delete(pending["handle"])

    with pytest.raises(UploadError, match="expired or was deleted"):
        store._append_bytes(upload_id, b"\x00" * 16)

    assert list(tmp_path.glob("*")) == []
