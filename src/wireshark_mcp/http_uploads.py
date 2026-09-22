"""HTTP upload route: raw capture bytes in, an ``upload://`` handle out.

The base64 upload tool routes every byte through the calling model's context,
which caps practical uploads at a few hundred KB. This route takes the same
capture as a raw ``application/octet-stream`` body instead, so a client can hand
the server a real-sized capture with ``curl`` and pass only the returned handle
to the analysis tools.

Behind an MCP gateway the route is reached through the gateway's HTTP
passthrough, typically via a short-lived upload URL the gateway mints for a
model-driven agent that has no bearer token of its own. The gateway relays 4xx
bodies verbatim, so every rejection carries the same JSON envelope the tools use
and an actionable message.

The route is registered with ``MCPServer.custom_route``, which the SDK adds to
both the Streamable HTTP and SSE apps; stdio has no HTTP surface and ignores it.
Like the upload tools it is registered unconditionally and answers 403 while
uploads are disabled. It adds nothing to ``tools/list``.

| Condition                         | Status |
|-----------------------------------|--------|
| Stored and readable               | 201    |
| Empty body                        | 400    |
| Uploads disabled                  | 403    |
| Over the per-upload cap           | 413    |
| Not a pcap/pcapng                 | 415    |
| ``capinfos`` cannot read it       | 422    |
| Upload directory quota exhausted  | 507    |
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from starlette.requests import ClientDisconnect
from starlette.responses import JSONResponse, Response

from .tools.envelope import error_response
from .tools.uploads import verify_readable
from .uploads import UploadError

if TYPE_CHECKING:
    from mcp.server import MCPServer
    from starlette.requests import Request

    from .tshark.client import TSharkClient
    from .uploads import UploadStore

logger = logging.getLogger("wireshark_mcp")

UPLOAD_ROUTE_PATH = "/uploads"


def _declared_size(request: Request) -> int | None:
    """The ``Content-Length`` header as an int, or ``None`` if absent or bogus.

    A bogus value is ignored rather than rejected: the streamed byte count is what
    the store enforces, so the header only ever serves to reject early.
    """
    raw = request.headers.get("content-length", "").strip()
    return int(raw) if raw.isdigit() else None


def _failure(exc: UploadError) -> JSONResponse:
    return JSONResponse(json.loads(error_response(exc.message, exc.error_type)), status_code=exc.status)


def register_upload_routes(mcp: MCPServer, client: TSharkClient, store: UploadStore) -> None:
    """Register ``POST /uploads`` on the server's HTTP apps."""

    async def upload_capture(request: Request) -> Response:
        filename = request.query_params.get("filename", "")
        try:
            record = await store.ingest_stream(
                request.stream(),
                filename=filename,
                declared_size=_declared_size(request),
            )
            await verify_readable(client, store, record)
        except UploadError as exc:
            return _failure(exc)
        except ClientDisconnect:
            # The store already removed the partial; nobody is left to answer.
            logger.info("Upload aborted: client disconnected")
            return Response(status_code=400)
        return JSONResponse({"success": True, "data": record}, status_code=201)

    # Applied as a call, not decorator syntax: the SDK's decorator is untyped and
    # would erase the handler's signature under mypy --strict.
    mcp.custom_route(UPLOAD_ROUTE_PATH, methods=["POST"], include_in_schema=False)(upload_capture)
