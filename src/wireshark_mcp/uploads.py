"""Capture upload store for deployments that do not share a filesystem.

Every analysis tool takes a ``pcap_file`` path, which assumes the MCP server and
the agent driving it can see the same disk. That assumption breaks the moment the
server runs somewhere else — the case this module exists for.

Three properties of a gateway-fronted deployment shape the design, and none of
them is negotiable from here:

* **No caller identity reaches the server.** An MCP gateway that follows the
  authorization spec must not forward the client's token upstream, so a backend
  sees only the gateway's own credentials. There is nothing to scope an upload
  to — no user, no tenant, no claim.
* **No session outlives a call.** A proxying gateway typically opens a fresh
  upstream session per request, so the upload call and the analysis call that
  follows it arrive on different sessions. Session-keyed storage would lose the
  file between the two.
* **Bytes arrive as tool arguments.** Tools are the only client-to-server channel
  a gateway forwards, so content comes in base64-encoded, in one call or in
  chunks.

What is left is a *capability*: an unguessable ``upload://<32 hex>`` handle whose
possession is the authorization. That is weaker than per-user access control and
is deliberately not dressed up as more — handles are minted from
``secrets.token_hex`` (128 bits), expire, and can be deleted explicitly.

The store is opt-in. With no upload directory configured it reports
``enabled == False`` and every tool fails closed with ``PermissionDenied``,
matching how 3.0 treats file-writing tools when ``WIRESHARK_MCP_ALLOWED_DIRS``
is unset.

Expiry is swept lazily, at the start of each operation, rather than by a
background task: a container that is idle has nothing to run, and there is no
task to leak or to outlive the event loop.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = logging.getLogger("wireshark_mcp")

UPLOAD_DIR_ENV = "WIRESHARK_MCP_UPLOAD_DIR"
MAX_UPLOAD_BYTES_ENV = "WIRESHARK_MCP_MAX_UPLOAD_BYTES"
UPLOAD_TTL_ENV = "WIRESHARK_MCP_UPLOAD_TTL"
MAX_UPLOAD_TOTAL_BYTES_ENV = "WIRESHARK_MCP_MAX_UPLOAD_TOTAL_BYTES"

DEFAULT_MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MiB
DEFAULT_UPLOAD_TTL_SECONDS = 3600  # 1 hour
DEFAULT_MAX_UPLOAD_TOTAL_BYTES = 1024 * 1024 * 1024  # 1 GiB across all live uploads

# Streamed bodies are written in blocks of this size. Each block is one quota
# reservation and one hop to a worker thread, so it trades a little memory for
# not paying either cost on every few-KB network read.
STREAM_BLOCK_BYTES = 1024 * 1024

# Name of the directory created under the first allowed root when no explicit
# upload directory is configured.
DEFAULT_UPLOAD_DIR_NAME = "uploads"

UPLOAD_SCHEME = "upload://"
_HANDLE_RE = re.compile(r"upload://([0-9a-f]{32})")
# A handle on its own, used when validating a caller-supplied argument.
_EXACT_HANDLE_RE = re.compile(r"^upload://([0-9a-f]{32})$")

# Capture-file magic numbers, checked before anything is handed to the Wireshark
# suite. This is a cheap gate against a caller storing arbitrary content in the
# server's sandbox, not a format guarantee — `capinfos` provides that afterwards.
_PCAP_MAGICS: tuple[bytes, ...] = (
    b"\xa1\xb2\xc3\xd4",  # pcap, big-endian, microsecond
    b"\xd4\xc3\xb2\xa1",  # pcap, little-endian, microsecond
    b"\xa1\xb2\x3c\x4d",  # pcap, big-endian, nanosecond
    b"\x4d\x3c\xb2\xa1",  # pcap, little-endian, nanosecond
)
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"  # pcapng Section Header Block


class UploadError(Exception):
    """A caller-visible upload failure.

    ``error_type`` maps onto the envelope's ``error.type`` so the tool layer can
    report the same taxonomy the rest of the server uses. ``status`` is the HTTP
    status the upload route answers with; tools ignore it.
    """

    def __init__(self, message: str, error_type: str = "InvalidParameter", *, status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.error_type = error_type
        self.status = status


def detect_capture_format(head: bytes) -> str | None:
    """Return ``"pcap"``, ``"pcapng"``, or ``None`` for a file's leading bytes."""
    if head.startswith(_PCAPNG_MAGIC):
        return "pcapng"
    if any(head.startswith(magic) for magic in _PCAP_MAGICS):
        return "pcap"
    return None


def _not_a_capture(what: str) -> UploadError:
    return UploadError(f"{what} is not a pcap or pcapng capture (magic number check failed).", status=415)


def _positive_int_env(name: str, default: int) -> int:
    """Read a positive integer from the environment, falling back on nonsense."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Ignoring non-integer %s=%r", name, raw)
        return default
    if value <= 0:
        logger.warning("Ignoring non-positive %s=%r", name, raw)
        return default
    return value


def _sanitize_filename(filename: str) -> str:
    """Reduce a caller-supplied name to a harmless label.

    The result is only ever used for display and to pick a file extension; the
    stored path is derived from the handle, never from this. Taking the basename
    of both separator styles keeps a Windows-style name from smuggling a
    directory component onto a POSIX server.
    """
    base = filename.replace("\\", "/").rsplit("/", 1)[-1].strip()
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")
    return cleaned[:128]


class UploadStore:
    """Capability-addressed storage for captures uploaded over MCP.

    A record is a pair of files under the upload directory: ``<id>.json`` holding
    metadata and ``<id>.<ext>`` holding the bytes. A partial upload uses the
    extension ``part`` and carries ``"complete": false``, so an interrupted
    chunked transfer can never be resolved and analyzed as if it were whole.
    """

    def __init__(
        self,
        directory: Path,
        *,
        max_bytes: int,
        ttl_seconds: int,
        max_total_bytes: int = DEFAULT_MAX_UPLOAD_TOTAL_BYTES,
    ) -> None:
        self._dir = directory
        self._max_bytes = max_bytes
        self._ttl = ttl_seconds
        self._max_total_bytes = max_total_bytes
        # Store operations run on worker threads so large writes do not stall the
        # event loop. The lock makes each quota check atomic with the reservation
        # that follows it; data is written outside it.
        self._lock = threading.Lock()

    # ── Introspection ───────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        """Whether uploads are configured. A disabled store fails every call."""
        return True

    @property
    def directory(self) -> Path:
        return self._dir

    @property
    def max_bytes(self) -> int:
        return self._max_bytes

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    @property
    def max_total_bytes(self) -> int:
        return self._max_total_bytes

    # ── Internal helpers ────────────────────────────────────────────────

    def _meta_path(self, upload_id: str) -> Path:
        return self._dir / f"{upload_id}.json"

    def _read_meta(self, upload_id: str) -> dict[str, Any] | None:
        try:
            raw = self._meta_path(upload_id).read_text(encoding="utf-8")
        except OSError:
            return None
        try:
            meta = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return None
        return meta if isinstance(meta, dict) else None

    def _write_meta(self, upload_id: str, meta: dict[str, Any]) -> None:
        # Write-then-rename so a crash mid-write cannot leave metadata that
        # parses as a complete upload pointing at a truncated file.
        tmp = self._dir / f"{upload_id}.json.tmp"
        tmp.write_text(json.dumps(meta), encoding="utf-8")
        tmp.replace(self._meta_path(upload_id))

    def _remove(self, upload_id: str) -> None:
        meta = self._read_meta(upload_id)
        if meta is not None:
            data_name = meta.get("stored_name")
            if isinstance(data_name, str) and data_name:
                # Resolve through the directory so a tampered sidecar cannot
                # point the unlink at a path outside the upload sandbox.
                candidate = self._dir / Path(data_name).name
                candidate.unlink(missing_ok=True)
        self._meta_path(upload_id).unlink(missing_ok=True)

    def _used_bytes(self) -> int:
        """Bytes held by every live record, partial ones included.

        A partial record's ``size`` is a reservation: it is raised before the
        bytes are written, so concurrent transfers cannot jointly overshoot.
        """
        total = 0
        try:
            entries = list(self._dir.glob("*.json"))
        except OSError:
            return 0
        for meta_path in entries:
            meta = self._read_meta(meta_path.stem)
            size = meta.get("size") if meta else None
            if isinstance(size, int):
                total += size
        return total

    def _check_quota(self, additional: int) -> None:
        """Raise unless ``additional`` more bytes fit. Call with the lock held."""
        used = self._used_bytes()
        if used + additional > self._max_total_bytes:
            raise UploadError(
                f"Upload storage is full: {used} of {self._max_total_bytes} bytes in use, "
                f"{additional} more requested. Delete uploads that are no longer needed "
                f"or raise {MAX_UPLOAD_TOTAL_BYTES_ENV}.",
                "QuotaExceeded",
                status=507,
            )

    def _new_record(self, filename: str, size: int) -> tuple[str, dict[str, Any]]:
        """Create an empty ``.part`` file and its sidecar, reserving ``size`` bytes.

        Call with the lock held, so the quota check before it and the reservation
        here cannot be split by another transfer.
        """
        upload_id = secrets.token_hex(16)
        part_path = self._dir / f"{upload_id}.part"
        try:
            # 0600: the sandbox directory is already private, but an upload is
            # caller-supplied content and need not be group- or world-readable.
            os.close(os.open(part_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        except OSError as exc:
            raise UploadError(f"Could not create upload: {exc}", "PermissionDenied", status=500) from exc
        meta: dict[str, Any] = {
            "id": upload_id,
            "created_at": time.time(),
            "filename": _sanitize_filename(filename),
            "stored_name": part_path.name,
            "size": size,
            "complete": False,
        }
        self._write_meta(upload_id, meta)
        return upload_id, meta

    def _append_bytes(self, upload_id: str, data: bytes) -> None:
        """Append to an existing ``.part`` file, never creating one.

        Without ``O_CREAT`` a record deleted or swept mid-transfer fails here,
        instead of leaving behind an orphaned data file no sidecar points at —
        which nothing would ever sweep.
        """
        part_path = self._dir / f"{upload_id}.part"
        try:
            fd = os.open(part_path, os.O_WRONLY | os.O_APPEND)
        except FileNotFoundError as exc:
            raise UploadError(
                f"Upload {UPLOAD_SCHEME}{upload_id} expired or was deleted during the transfer.",
                "FileNotFound",
                status=404,
            ) from exc
        except OSError as exc:
            raise UploadError(f"Could not write upload: {exc}", "PermissionDenied", status=500) from exc
        try:
            with os.fdopen(fd, "ab") as handle_out:
                handle_out.write(data)
        except OSError as exc:
            raise UploadError(f"Could not write upload: {exc}", "PermissionDenied", status=500) from exc

    def _over_cap(self, size: int, *, discarded: bool) -> UploadError:
        suffix = " The partial upload was discarded." if discarded else ""
        return UploadError(
            f"Upload reaches {size} bytes, over the {self._max_bytes} byte limit.{suffix} "
            f"Raise {MAX_UPLOAD_BYTES_ENV} or trim the capture with editcap.",
            "InvalidParameter",
            status=413,
        )

    @staticmethod
    def _parse_handle(handle: str) -> str:
        match = _EXACT_HANDLE_RE.match(handle.strip())
        if match is None:
            raise UploadError(f"Not an upload handle: {handle!r}. Expected {UPLOAD_SCHEME}<32 hex characters>.")
        return match.group(1)

    def _decode(self, content_base64: str) -> bytes:
        # Strip whitespace some clients insert when wrapping long base64 lines.
        payload = "".join(content_base64.split())
        if not payload:
            raise UploadError("content_base64 is empty")
        try:
            return base64.b64decode(payload, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise UploadError(f"content_base64 is not valid base64: {exc}") from exc

    # ── Lifecycle ───────────────────────────────────────────────────────

    def sweep(self) -> int:
        """Delete uploads older than the TTL. Returns how many were removed.

        Age is taken from the recorded creation time rather than file mtime, so
        appending a chunk does not extend a slow transfer's lease indefinitely.
        """
        if self._ttl <= 0:
            return 0
        with self._lock:
            return self._sweep_locked()

    def _sweep_locked(self) -> int:
        cutoff = time.time() - self._ttl
        removed = 0
        try:
            entries = sorted(self._dir.glob("*.json"))
        except OSError:
            return 0
        for meta_path in entries:
            upload_id = meta_path.stem
            meta = self._read_meta(upload_id)
            created = meta.get("created_at") if meta else None
            if not isinstance(created, (int, float)):
                # Unreadable sidecar: fall back to mtime so a corrupt record is
                # still reclaimed instead of pinning disk forever.
                try:
                    created = meta_path.stat().st_mtime
                except OSError:
                    continue
            if created < cutoff:
                self._remove(upload_id)
                removed += 1
        if removed:
            logger.info("Swept %d expired upload(s)", removed)
        return removed

    def write(
        self,
        content_base64: str,
        *,
        filename: str = "",
        handle: str = "",
        more_chunks: bool = False,
    ) -> dict[str, Any]:
        """Store bytes, either as a whole capture or as one chunk of one.

        With no ``handle`` a new record is created; with one, the bytes are
        appended to that record, which must still be incomplete. ``more_chunks``
        leaves the record open for a further append. The record is finalized —
        magic-number checked and renamed to its real extension — on the call that
        passes ``more_chunks=False``.
        """
        self.sweep()
        data = self._decode(content_base64)

        if handle:
            return self._append(self._parse_handle(handle), data, more_chunks=more_chunks)
        return self._create(data, filename=filename, more_chunks=more_chunks)

    def _create(self, data: bytes, *, filename: str, more_chunks: bool) -> dict[str, Any]:
        if len(data) > self._max_bytes:
            raise self._over_cap(len(data), discarded=False)
        if not more_chunks and detect_capture_format(data[:4]) is None:
            raise _not_a_capture("Content")

        with self._lock:
            self._check_quota(len(data))
            upload_id, meta = self._new_record(filename, len(data))
        try:
            self._append_bytes(upload_id, data)
        except UploadError:
            self._remove(upload_id)
            raise

        if more_chunks:
            return self._public(meta)
        return self._finalize(upload_id, meta)

    def _append(self, upload_id: str, data: bytes, *, more_chunks: bool) -> dict[str, Any]:
        meta = self._read_meta(upload_id)
        if meta is None:
            raise UploadError(f"Unknown or expired upload: {UPLOAD_SCHEME}{upload_id}", "FileNotFound", status=404)
        if meta.get("complete"):
            raise UploadError(f"Upload {UPLOAD_SCHEME}{upload_id} is already complete; start a new upload instead.")

        size = int(meta.get("size", 0))
        if size + len(data) > self._max_bytes:
            # Drop the partial record rather than leaving a stalled transfer to
            # occupy the sandbox until its TTL expires.
            self._remove(upload_id)
            raise self._over_cap(size + len(data), discarded=True)

        # A quota refusal keeps the partial: the caller can free space and resend
        # this chunk, which a streamed body (already consumed) could not.
        meta = self._reserve(upload_id, len(data))
        try:
            self._append_bytes(upload_id, data)
        except UploadError:
            self._remove(upload_id)
            raise

        if more_chunks:
            return self._public(meta)
        return self._finalize(upload_id, meta)

    def _finalize(self, upload_id: str, meta: dict[str, Any]) -> dict[str, Any]:
        """Check the magic number and give the record its real extension."""
        part_path = self._dir / f"{upload_id}.part"
        try:
            with open(part_path, "rb") as handle_in:
                head = handle_in.read(4)
        except OSError as exc:
            self._remove(upload_id)
            raise UploadError(f"Could not read upload: {exc}", "PermissionDenied", status=500) from exc

        capture_format = detect_capture_format(head)
        if capture_format is None:
            self._remove(upload_id)
            raise _not_a_capture("Assembled content")

        final_path = self._dir / f"{upload_id}.{capture_format}"
        try:
            part_path.replace(final_path)
        except OSError as exc:
            self._remove(upload_id)
            raise UploadError(f"Could not finalize upload: {exc}", "PermissionDenied", status=500) from exc

        meta["stored_name"] = final_path.name
        meta["format"] = capture_format
        meta["complete"] = True
        self._write_meta(upload_id, meta)
        logger.info("Stored upload %s (%s, %d bytes)", upload_id, capture_format, meta["size"])
        return self._public(meta)

    def _reserve(self, upload_id: str, additional: int) -> dict[str, Any]:
        """Grow a partial record's reservation by ``additional`` bytes, atomically."""
        with self._lock:
            meta = self._read_meta(upload_id)
            if meta is None:
                raise UploadError(
                    f"Upload {UPLOAD_SCHEME}{upload_id} expired or was deleted during the transfer.",
                    "FileNotFound",
                    status=404,
                )
            self._check_quota(additional)
            meta["size"] = int(meta.get("size", 0)) + additional
            self._write_meta(upload_id, meta)
            return meta

    def _begin_stream(self, filename: str, declared_size: int | None) -> str:
        self.sweep()
        if declared_size is not None and declared_size > self._max_bytes:
            raise self._over_cap(declared_size, discarded=False)
        with self._lock:
            # Checking the declared size up front answers 507 before the client
            # sends the body; the per-block reservations below stay authoritative.
            if declared_size is not None:
                self._check_quota(declared_size)
            upload_id, _ = self._new_record(filename, 0)
        return upload_id

    def _write_block(self, upload_id: str, block: bytes) -> None:
        self._reserve(upload_id, len(block))
        self._append_bytes(upload_id, block)

    async def ingest_stream(
        self,
        chunks: AsyncIterator[bytes],
        *,
        filename: str = "",
        declared_size: int | None = None,
    ) -> dict[str, Any]:
        """Store a raw capture body arriving as a byte stream.

        The HTTP counterpart of :meth:`write`: no base64, no chunk protocol, and
        no need to hold the body in memory. Blocks are written on a worker thread
        so a large transfer does not stall other requests. The per-upload cap is
        enforced on the running total and the directory quota on each block, and
        any failure — a limit, a bad magic number, the client going away —
        removes the partial record, since a consumed stream cannot be resumed.
        """
        upload_id = await asyncio.to_thread(self._begin_stream, filename, declared_size)
        received = 0
        buffer = bytearray()
        try:
            async for chunk in chunks:
                if not chunk:
                    continue
                received += len(chunk)
                if received > self._max_bytes:
                    raise self._over_cap(received, discarded=True)
                buffer += chunk
                if len(buffer) >= STREAM_BLOCK_BYTES:
                    await asyncio.to_thread(self._write_block, upload_id, bytes(buffer))
                    buffer.clear()
            if buffer:
                await asyncio.to_thread(self._write_block, upload_id, bytes(buffer))
            if received == 0:
                raise UploadError("Upload body is empty.")
            meta = await asyncio.to_thread(self._read_meta, upload_id)
            if meta is None:
                raise UploadError(
                    f"Upload {UPLOAD_SCHEME}{upload_id} expired or was deleted during the transfer.",
                    "FileNotFound",
                    status=404,
                )
            return await asyncio.to_thread(self._finalize, upload_id, meta)
        except BaseException:
            # BaseException, not Exception: a cancelled request (client gone)
            # must not leave its partial behind either. Synchronous on purpose —
            # there may be no event loop turn left to await a thread. The lock
            # keeps a still-running block write from re-creating the sidecar
            # between its read and its write.
            with self._lock:
                self._remove(upload_id)
            raise

    def discard(self, handle: str) -> None:
        """Remove a record without reporting whether it existed.

        Used to clean up an upload that passed the magic check but failed the
        `capinfos` probe, so a file the suite cannot read is never left behind.
        """
        try:
            self._remove(self._parse_handle(handle))
        except UploadError:
            return

    # ── Access ──────────────────────────────────────────────────────────

    def resolve(self, handle: str) -> Path:
        """Map a handle to the stored path, or raise ``UploadError``."""
        upload_id = self._parse_handle(handle)
        meta = self._read_meta(upload_id)
        if meta is None:
            raise UploadError(
                f"Unknown or expired upload: {handle}. Uploads expire after {self._ttl} seconds.",
                "FileNotFound",
                status=404,
            )
        if not meta.get("complete"):
            raise UploadError(
                f"Upload {handle} is still incomplete; send the final chunk with more_chunks=false.",
                "InvalidParameter",
            )
        stored_name = meta.get("stored_name")
        if not isinstance(stored_name, str) or not stored_name:
            raise UploadError(f"Upload {handle} has no stored file", "FileNotFound")
        path = self._dir / Path(stored_name).name
        if not path.is_file():
            raise UploadError(f"Upload {handle} is no longer on disk", "FileNotFound")
        return path

    def expand(self, text: str) -> str:
        """Replace every handle in a string with its resolved path.

        Operating on substrings rather than whole values keeps comma-separated
        arguments such as ``input_files`` working without the tool layer
        knowing which parameters may hold several paths.
        """
        if UPLOAD_SCHEME not in text:
            return text

        def substitute(match: re.Match[str]) -> str:
            return str(self.resolve(match.group(0)))

        return _HANDLE_RE.sub(substitute, text)

    def list_uploads(self) -> list[dict[str, Any]]:
        """Every live record, oldest first."""
        self.sweep()
        records: list[dict[str, Any]] = []
        try:
            entries = sorted(self._dir.glob("*.json"))
        except OSError:
            return records
        for meta_path in entries:
            meta = self._read_meta(meta_path.stem)
            if meta is not None:
                records.append(self._public(meta))
        records.sort(key=lambda record: record["created_at"])
        return records

    def delete(self, handle: str) -> bool:
        """Delete a record. Returns whether it existed."""
        upload_id = self._parse_handle(handle)
        with self._lock:
            existed = self._read_meta(upload_id) is not None
            self._remove(upload_id)
        if existed:
            logger.info("Deleted upload %s", upload_id)
        return existed

    def _public(self, meta: dict[str, Any]) -> dict[str, Any]:
        """The caller-facing view of a record.

        The server-side path is deliberately absent: the handle is the only
        reference a caller needs, and echoing the real path would put the
        server's filesystem layout into the model's transcript.
        """
        created = meta.get("created_at", 0.0)
        expires_in = None
        if self._ttl > 0 and isinstance(created, (int, float)):
            expires_in = max(0, int(created + self._ttl - time.time()))
        record: dict[str, Any] = {
            "handle": f"{UPLOAD_SCHEME}{meta.get('id', '')}",
            "size": meta.get("size", 0),
            "complete": bool(meta.get("complete")),
            "created_at": created,
        }
        if meta.get("filename"):
            record["filename"] = meta["filename"]
        if meta.get("format"):
            record["format"] = meta["format"]
        if expires_in is not None:
            record["expires_in_seconds"] = expires_in
        return record


class DisabledUploadStore(UploadStore):
    """Stand-in used when no upload directory is configured.

    Registering the upload tools unconditionally and failing here keeps the
    advertised tool list identical whether or not uploads are configured, which
    is what the client's cached prompt prefix depends on. It also matches how the
    file-writing tools behave without ``WIRESHARK_MCP_ALLOWED_DIRS``.
    """

    def __init__(self) -> None:
        super().__init__(Path(), max_bytes=DEFAULT_MAX_UPLOAD_BYTES, ttl_seconds=DEFAULT_UPLOAD_TTL_SECONDS)

    @property
    def enabled(self) -> bool:
        return False

    def _unavailable(self) -> UploadError:
        return UploadError(
            f"Capture uploads are disabled. Set {UPLOAD_DIR_ENV} to a dedicated writable "
            f"directory (or set WIRESHARK_MCP_ALLOWED_DIRS, which puts uploads in a "
            f"{DEFAULT_UPLOAD_DIR_NAME!r} subdirectory of the first entry).",
            "PermissionDenied",
            status=403,
        )

    def sweep(self) -> int:
        return 0

    def write(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        raise self._unavailable()

    async def ingest_stream(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        raise self._unavailable()

    def resolve(self, handle: str) -> Path:
        raise self._unavailable()

    def expand(self, text: str) -> str:
        if UPLOAD_SCHEME in text:
            raise self._unavailable()
        return text

    def list_uploads(self) -> list[dict[str, Any]]:
        raise self._unavailable()

    def delete(self, handle: str) -> bool:
        raise self._unavailable()

    def discard(self, handle: str) -> None:
        return


def resolve_upload_dir(allowed_dirs: list[str] | None) -> Path | None:
    """Decide where uploads live, or ``None`` when the feature is not configured.

    An explicit ``WIRESHARK_MCP_UPLOAD_DIR`` wins. Otherwise uploads land in a
    dedicated subdirectory of the first allowed root, so a deployment that has
    already opted into a writable sandbox does not need a second variable — but
    they stay in their own directory rather than mixing with analysis output.
    """
    configured = os.environ.get(UPLOAD_DIR_ENV, "").strip()
    if configured:
        return Path(configured).expanduser()
    if allowed_dirs:
        return Path(allowed_dirs[0]).expanduser() / DEFAULT_UPLOAD_DIR_NAME
    return None


def create_upload_store(allowed_dirs: list[str] | None) -> UploadStore:
    """Build the upload store for this process.

    Returns a :class:`DisabledUploadStore` when nothing is configured or the
    directory cannot be created, so a misconfiguration surfaces as a clear
    per-call error rather than a failure to start.
    """
    directory = resolve_upload_dir(allowed_dirs)
    if directory is None:
        return DisabledUploadStore()

    try:
        directory.mkdir(parents=True, exist_ok=True)
        # Best effort: on Windows, and on a pre-existing directory owned by
        # someone else, this is not something to fail startup over.
        os.chmod(directory, 0o700)
    except OSError as exc:
        logger.warning("Capture uploads disabled: cannot use %s (%s)", directory, exc)
        return DisabledUploadStore()

    resolved = directory.resolve()
    store = UploadStore(
        resolved,
        max_bytes=_positive_int_env(MAX_UPLOAD_BYTES_ENV, DEFAULT_MAX_UPLOAD_BYTES),
        ttl_seconds=_positive_int_env(UPLOAD_TTL_ENV, DEFAULT_UPLOAD_TTL_SECONDS),
        max_total_bytes=_positive_int_env(MAX_UPLOAD_TOTAL_BYTES_ENV, DEFAULT_MAX_UPLOAD_TOTAL_BYTES),
    )
    logger.info(
        "Capture uploads enabled at %s (max %d bytes each, %d total, TTL %d seconds)",
        resolved,
        store.max_bytes,
        store.max_total_bytes,
        store.ttl_seconds,
    )
    return store
