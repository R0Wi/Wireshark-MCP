# Capture Upload

[中文版](capture-upload_zh.md)

Every analysis tool takes a `pcap_file` path. That assumes the server and the
agent driving it can see the same disk — true on a desktop, false as soon as the
server runs somewhere else. Capture upload removes the assumption: the client
sends the bytes over MCP and gets back a handle that every existing tool accepts.

```
wireshark_upload_capture  →  upload://a12183de1c1a21ee6c058b5610a5ab08
                                        ↓
                             wireshark_aggregate(pcap_file="upload://a121…")
```

No tool signature changed. A handle is resolved to its stored path centrally,
before the call is dispatched, so the whole surface accepts one without knowing
uploads exist.

## Enabling it

Uploads are off until a directory is configured, and every upload tool returns
`PermissionDenied` until then.

```sh
export WIRESHARK_MCP_ALLOWED_DIRS=/srv/pcaps
wireshark-mcp serve --transport streamable-http --host 127.0.0.1 --port 8080
```

That puts uploads in `/srv/pcaps/uploads`, which requires `/srv/pcaps` to be
writable. If your first allowed directory is a read-only capture mount — the
arrangement [Deployment scenarios](deployment-scenarios.md) recommends — the
directory cannot be created, uploads stay disabled, and the server logs a
warning at startup. Point them somewhere writable instead.

To keep uploads elsewhere generally — a tmpfs, a volume with its own quota —
set the directory explicitly:

```sh
export WIRESHARK_MCP_UPLOAD_DIR=/run/wireshark-uploads
```

An upload directory outside `WIRESHARK_MCP_ALLOWED_DIRS` is added to the
read sandbox automatically, so a resolved handle does not fail the path check it
just opted into.

| Variable | Default | Purpose |
|----------|---------|---------|
| `WIRESHARK_MCP_UPLOAD_DIR` | `<first allowed dir>/uploads` | Where uploads are stored. Unset **and** no allowed dirs means uploads are disabled. |
| `WIRESHARK_MCP_MAX_UPLOAD_BYTES` | `104857600` (100 MiB) | Largest single capture, counted after base64 decoding. |
| `WIRESHARK_MCP_UPLOAD_TTL` | `3600` (1 hour) | How long an upload survives before it is swept. |

Expiry is swept lazily, at the start of each upload operation. There is no
background task, so an idle server does nothing and a container has no timer to
outlive.

## Uploading

A capture that fits in one call:

```jsonc
// wireshark_upload_capture
{ "content_base64": "1MOyoQIABAA…", "filename": "incident.pcap" }
```

A larger one, in parts. Pass `more_chunks: true` on every part but the last, and
feed the returned handle back:

```jsonc
{ "content_base64": "1MOyoQIABAA…", "filename": "incident.pcap", "more_chunks": true }
// → { "handle": "upload://a121…", "complete": false }

{ "content_base64": "AAECAwQF…", "upload_handle": "upload://a121…", "more_chunks": true }
{ "content_base64": "9fb3+Pn6…", "upload_handle": "upload://a121…" }
// → { "handle": "upload://a121…", "complete": true, "format": "pcap", "size": 4008 }
```

A partial upload cannot be analyzed: resolving an incomplete handle fails until
the final part arrives.

Then analyze it exactly as you would a local path:

```jsonc
{ "pcap_file": "upload://a121…", "group_by": "dns.qry.name", "top_k": 10 }
```

`wireshark_list_uploads` shows what the server currently holds and how long each
upload has left; `wireshark_delete_upload` removes one immediately.

### Practical size limits

Base64 costs about 33% in transfer, but the real constraint is different: a tool
argument is produced by the model, so an uploaded capture passes through its
context window. A few hundred KB is comfortable; tens of megabytes is not,
whatever `WIRESHARK_MCP_MAX_UPLOAD_BYTES` allows. Chunking splits the cost over
several calls but does not remove it.

For a large capture, prefer trimming it at the source — `editcap -A/-B` for a
time window, or a capture filter — over uploading everything and filtering
server-side. A client driving the MCP session programmatically rather than
through a model does not have this ceiling and can use the full 100 MiB.

## Behind an MCP gateway

The intended deployment is a gateway that authenticates clients and proxies MCP
to this server. Two properties of that arrangement shape what uploads can
promise, and both are worth understanding before exposing the feature.

**The server sees no caller identity.** A gateway that follows the MCP
authorization spec must not forward the client's token upstream, so this server
receives only the gateway's own credentials. There is no user, tenant, or claim
to bind an upload to.

**Sessions do not persist.** A proxying gateway typically opens a fresh upstream
session per request, so the upload call and the analysis call that follows it
arrive on different MCP sessions. Storage keyed by session would lose the file
between the two.

What is left is a capability: the `upload://` handle is a 128-bit random token,
and possession of it is the authorization. Anyone who can reach the server *and*
knows a handle can read that capture. This is weaker than per-user access
control, and it is the strongest thing the server can enforce on its own.

In practice that means:

- **Keep the server unreachable except through the gateway.** The handle is not
  a substitute for the gateway's authentication; it only stops one client
  guessing another's upload.
- **Uploads are shared across clients of one gateway.** `wireshark_list_uploads`
  shows every live upload. Do not point several mutually untrusting tenants at a
  single server instance — run one per trust domain.
- **Keep the TTL short.** It is the main bound on how long a leaked handle stays
  useful.
- **Disk is a shared resource.** The size cap is per upload, not per directory.
  A dedicated volume or tmpfs with its own quota keeps a busy session from
  filling the host.

## What is checked

An upload is validated before it can be analyzed:

- **Magic number.** Content must start with a pcap or pcapng signature. A
  chunked upload is checked once assembled.
- **Readability.** `capinfos` must be able to open the finished file. An upload
  that fails is deleted rather than left for the first analysis call to trip on.
  Skipped when `capinfos` is not installed.
- **Size.** Enforced on each chunk against the running total, so a chunked
  upload cannot exceed the cap by arriving in pieces.
- **Filename.** Used only as a label; the stored path is derived from the
  handle, never from caller input.

Uploads are written `0600` in a `0700` directory, and the server-side path is
never returned to the caller.

## Container example

```sh
docker run --rm -p 127.0.0.1:8080:8080 \
  --tmpfs /uploads:rw,size=512m,mode=0700 \
  -v "$PWD/captures:/captures:ro" \
  -e WIRESHARK_MCP_ALLOWED_DIRS=/captures \
  -e WIRESHARK_MCP_UPLOAD_DIR=/uploads \
  -e WIRESHARK_MCP_UPLOAD_TTL=1800 \
  ghcr.io/bx33661/wireshark-mcp:3.0.0
```

A tmpfs bounds the upload directory independently of the host disk and discards
its contents when the container stops. The read-only `/captures` mount still
works alongside it — uploads add a source of captures, they do not replace one.
