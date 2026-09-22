# Unreleased

## English

### Added

- **Capture upload over MCP** ([#37](https://github.com/bx33661/Wireshark-MCP/issues/37)).
  A server that does not share a filesystem with its client can now be handed a
  capture directly. `wireshark_upload_capture` takes base64 content — in one call
  or in chunks — and returns an `upload://<id>` handle that every existing tool
  accepts wherever it takes a `pcap_file`. `wireshark_list_uploads` and
  `wireshark_delete_upload` manage the stored set. No existing tool signature
  changed: handles are resolved centrally, before a call is dispatched.

  Disabled until an upload directory is configured, and failing closed with
  `PermissionDenied` until then. Configure with `WIRESHARK_MCP_UPLOAD_DIR`
  (default: an `uploads` subdirectory of the first `WIRESHARK_MCP_ALLOWED_DIRS`
  entry), `WIRESHARK_MCP_MAX_UPLOAD_BYTES` (default 100 MiB) and
  `WIRESHARK_MCP_UPLOAD_TTL` (default 1 hour, swept lazily).

  Content is checked against pcap/pcapng magic numbers and must be readable by
  `capinfos` before it can be analyzed; an incomplete chunked upload cannot be
  resolved. Handles are 128-bit random tokens: possession is the authorization,
  which is what a gateway-fronted deployment can actually enforce, since a
  spec-compliant MCP gateway forwards no caller identity upstream. See
  [Capture upload](../docs/capture-upload.md) for the model and its limits.

- **HTTP upload route for large captures.** `POST /uploads` accepts a raw
  `application/octet-stream` body and returns the same `upload://` handle, so a
  real-sized capture reaches the server without passing through a model's
  context. Served by the Streamable HTTP and SSE transports; adds nothing to
  `tools/list`. Rejections carry distinct statuses (413, 415, 422, 507, …) and
  the tool JSON envelope, so an MCP gateway's HTTP passthrough can relay them
  unchanged — see [R0Wi/mcp-gateway#16](https://github.com/R0Wi/mcp-gateway/issues/16)
  for the gateway side, including short-lived upload URLs for model-driven agents.
- **Upload directory quota.** `WIRESHARK_MCP_MAX_UPLOAD_TOTAL_BYTES` (default
  1 GiB) bounds all live uploads together, partial ones included. Space is
  reserved before it is written, so concurrent transfers cannot jointly
  overshoot it.

### Changed

- Upload file I/O now runs on a worker thread, for both the upload tools and the
  HTTP route, so a large write no longer stalls other requests.
- The advertised tool surface grows from 52 to 55 tools (~23 KB), and the
  `tools/list` byte budget from 22,500 to 23,500, to accommodate the three
  upload tools. They are registered unconditionally so the payload does not vary
  with deployment configuration.

## 中文

### 新增

- **通过 MCP 上传抓包**（[#37](https://github.com/bx33661/Wireshark-MCP/issues/37)）。
  与客户端不共享文件系统的服务端，现在可以直接接收抓包文件。
  `wireshark_upload_capture` 接受 base64 内容（单次或分片），返回 `upload://<id>`
  句柄；所有现有工具在接受 `pcap_file` 的位置都能使用该句柄。
  `wireshark_list_uploads` 与 `wireshark_delete_upload` 用于管理已存储的上传。
  没有任何现有工具签名发生变化：句柄在请求分发之前被统一解析。

  该功能在配置上传目录前处于关闭状态，此前一律以 `PermissionDenied` 失败。
  可通过 `WIRESHARK_MCP_UPLOAD_DIR`（默认为第一个 `WIRESHARK_MCP_ALLOWED_DIRS`
  条目下的 `uploads` 子目录）、`WIRESHARK_MCP_MAX_UPLOAD_BYTES`（默认 100 MiB）
  和 `WIRESHARK_MCP_UPLOAD_TTL`（默认 1 小时，惰性清理）配置。

  内容会校验 pcap/pcapng magic number，并且必须能被 `capinfos` 读取后才可用于分析；
  未完成的分片上传无法被解析。句柄是 128 位随机令牌：持有即授权——这正是网关前置部署
  实际能够强制的粒度，因为符合规范的 MCP 网关不会向上游转发调用方身份。
  模型与限制参见[抓包上传](../docs/capture-upload_zh.md)。

- **用于大抓包的 HTTP 上传路由。** `POST /uploads` 接受原始 `application/octet-stream`
  请求体，并返回同样的 `upload://` 句柄，因此真实大小的抓包无需经过模型上下文即可送达服务端。
  由 Streamable HTTP 与 SSE 传输提供，不增加 `tools/list` 的内容。各类拒绝对应不同状态码
  （413、415、422、507 等）并使用工具 JSON 信封，MCP 网关的 HTTP 透传可原样转发——
  网关侧（包括为模型驱动 Agent 签发短时上传 URL）参见
  [R0Wi/mcp-gateway#16](https://github.com/R0Wi/mcp-gateway/issues/16)。
- **上传目录配额。** `WIRESHARK_MCP_MAX_UPLOAD_TOTAL_BYTES`（默认 1 GiB）限制所有存活上传
  （含未完成的）的总量。空间在写入前预留，因此并发传输无法合计超出配额。

### 变更

- 上传工具与 HTTP 路由的文件 I/O 现在都在工作线程中执行，大文件写入不再阻塞其他请求。
- 对外暴露的工具面从 52 个增加到 55 个（约 23 KB），`tools/list` 字节预算
  从 22,500 提高到 23,500，以容纳三个上传工具。这些工具无条件注册，
  因此载荷不会随部署配置而变化。
