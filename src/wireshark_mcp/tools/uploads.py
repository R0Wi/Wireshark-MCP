"""Tools for getting a capture onto a server that does not share the caller's disk.

Three tools, not six: every entry in ``tools/list`` is re-sent on each request, and
the budget test in ``tests/test_prompt_cache.py`` holds the whole surface to a
fixed byte ceiling. Chunking is therefore folded into the upload tool as two
optional arguments rather than split across begin/append/finalize tools.

Store calls run on a worker thread: they do synchronous file I/O, and a tool
call must not stall every other request on the event loop while it writes.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from ..uploads import UploadError
from .envelope import envelope_response, error_response, parse_tool_result

if TYPE_CHECKING:
    from mcp.server import MCPServer

    from ..tshark.client import TSharkClient
    from ..uploads import UploadStore


def _failure(exc: UploadError) -> str:
    return error_response(exc.message, exc.error_type)


async def _capture_is_readable(client: TSharkClient, path: str) -> tuple[bool, str]:
    """Confirm the Wireshark suite can actually open a stored upload.

    The magic-number check in the store only proves the first four bytes look
    right. This catches a truncated or corrupt capture at upload time, where the
    caller can still do something about it, rather than on the first analysis
    call. It is skipped when `capinfos` is absent so a minimal image that ships
    only `tshark` can still accept uploads.
    """
    if not getattr(client, "capinfos_path", None):
        return True, ""
    result = parse_tool_result(await client.get_file_info(path))
    if result["success"]:
        return True, ""
    error = result.get("error") or {}
    return False, str(error.get("message") or "capinfos could not read the capture")


async def verify_readable(client: TSharkClient, store: UploadStore, record: dict[str, Any]) -> None:
    """Probe a finalized upload with `capinfos`, discarding it if unreadable.

    Shared by the upload tool and the HTTP upload route so both reject the same
    captures the same way. Raises ``UploadError`` (HTTP 422) on rejection.
    """
    path = await asyncio.to_thread(store.resolve, record["handle"])
    readable, reason = await _capture_is_readable(client, str(path))
    if not readable:
        await asyncio.to_thread(store.discard, record["handle"])
        raise UploadError(f"Upload rejected: the capture could not be read back. {reason}", status=422)


def register_upload_tools(mcp: MCPServer, client: TSharkClient, store: UploadStore) -> None:
    """Register the capture upload tools.

    Registered unconditionally: a tool list that changes with configuration would
    invalidate the client's cached prompt prefix. When no upload directory is
    configured the store is disabled and each tool returns ``PermissionDenied``.
    """

    @mcp.tool()
    async def wireshark_upload_capture(
        content_base64: str,
        filename: str = "",
        upload_handle: str = "",
        more_chunks: bool = False,
    ) -> str:
        """Upload a pcap/pcapng as base64; returns an upload:// handle any pcap_file argument accepts. Large capture: send parts with more_chunks=true, passing back the handle, then a last part with more_chunks=false."""
        try:
            record = await asyncio.to_thread(
                store.write,
                content_base64,
                filename=filename,
                handle=upload_handle,
                more_chunks=more_chunks,
            )
            if not record["complete"]:
                return envelope_response(
                    record,
                    warnings=["Upload is incomplete. Send the remaining parts with upload_handle set."],
                )
            await verify_readable(client, store, record)
        except UploadError as exc:
            return _failure(exc)
        return envelope_response(record)

    @mcp.tool()
    async def wireshark_list_uploads() -> str:
        """List captures held by this server with their upload:// handles and remaining lifetime."""
        try:
            records = await asyncio.to_thread(store.list_uploads)
        except UploadError as exc:
            return _failure(exc)
        return envelope_response({"uploads": records, "count": len(records)})

    @mcp.tool()
    async def wireshark_delete_upload(upload_handle: str) -> str:
        """Delete an uploaded capture now instead of waiting for it to expire."""
        try:
            existed = await asyncio.to_thread(store.delete, upload_handle)
        except UploadError as exc:
            return _failure(exc)
        if not existed:
            return error_response(f"Unknown or already removed upload: {upload_handle}", "FileNotFound")
        return envelope_response({"handle": upload_handle, "deleted": True})
