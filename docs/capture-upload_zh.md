# 抓包上传

[English](capture-upload.md)

所有分析工具都接受 `pcap_file` 路径，这隐含假设服务端与驱动它的 Agent 能看到同一块磁盘。
在桌面环境成立，但服务端一旦部署在别处就不再成立。抓包上传去掉了这个假设：客户端通过 MCP
发送字节，拿回一个所有现有工具都能接受的句柄。

```
wireshark_upload_capture  →  upload://a12183de1c1a21ee6c058b5610a5ab08
                                        ↓
                             wireshark_aggregate(pcap_file="upload://a121…")
```

没有任何工具签名发生变化。句柄在请求分发之前被统一解析为存储路径，因此整个工具面
都能接受句柄，而无需知道上传功能的存在。

## 启用

未配置目录前，上传处于关闭状态，所有上传工具都会返回 `PermissionDenied`。

```sh
export WIRESHARK_MCP_ALLOWED_DIRS=/srv/pcaps
wireshark-mcp serve --transport streamable-http --host 127.0.0.1 --port 8080
```

这会把上传放在 `/srv/pcaps/uploads`，因此要求 `/srv/pcaps` 可写。如果第一个允许目录是
只读的抓包挂载点——[部署场景](deployment-scenarios_zh.md)推荐的正是这种形式——
该目录无法创建，上传会保持关闭状态，服务端会在启动时记录一条警告。此时应把上传目录
指向可写位置。

若要把上传放在别处（例如 tmpfs，或带独立配额的卷），可显式指定目录：

```sh
export WIRESHARK_MCP_UPLOAD_DIR=/run/wireshark-uploads
```

位于 `WIRESHARK_MCP_ALLOWED_DIRS` 之外的上传目录会被自动加入读取沙箱，
以免解析后的句柄无法通过它刚刚启用的路径检查。

| 变量 | 默认值 | 用途 |
|------|--------|------|
| `WIRESHARK_MCP_UPLOAD_DIR` | `<第一个允许目录>/uploads` | 上传存放位置。未设置**且**没有允许目录时，上传功能关闭。 |
| `WIRESHARK_MCP_MAX_UPLOAD_BYTES` | `104857600`（100 MiB） | 单个抓包的大小上限，按 base64 解码后计算。 |
| `WIRESHARK_MCP_UPLOAD_TTL` | `3600`（1 小时） | 上传在被清理前的存活时间。 |

过期清理是惰性的，在每次上传操作开始时执行。没有后台任务，因此空闲的服务端不做任何事，
容器里也不会留下需要单独管理的定时器。

## 上传

单次调用即可完成的抓包：

```jsonc
// wireshark_upload_capture
{ "content_base64": "1MOyoQIABAA…", "filename": "incident.pcap" }
```

较大的抓包分片上传。除最后一片外，每片都传 `more_chunks: true`，并把返回的句柄传回：

```jsonc
{ "content_base64": "1MOyoQIABAA…", "filename": "incident.pcap", "more_chunks": true }
// → { "handle": "upload://a121…", "complete": false }

{ "content_base64": "AAECAwQF…", "upload_handle": "upload://a121…", "more_chunks": true }
{ "content_base64": "9fb3+Pn6…", "upload_handle": "upload://a121…" }
// → { "handle": "upload://a121…", "complete": true, "format": "pcap", "size": 4008 }
```

未完成的上传无法用于分析：在最后一片到达之前，解析不完整的句柄会失败。

随后就像使用本地路径一样分析它：

```jsonc
{ "pcap_file": "upload://a121…", "group_by": "dns.qry.name", "top_k": 10 }
```

`wireshark_list_uploads` 列出服务端当前持有的上传及各自剩余时间；
`wireshark_delete_upload` 可立即删除某个上传。

### 实际的大小限制

base64 在传输上约有 33% 开销，但真正的约束在别处：工具参数由模型生成，
因此上传的抓包会经过模型的上下文窗口。几百 KB 是舒适的，几十 MB 则不是，
无论 `WIRESHARK_MCP_MAX_UPLOAD_BYTES` 允许多大。分片只是把开销分摊到多次调用，
并不能消除它。

对于大抓包，优先在源头裁剪——用 `editcap -A/-B` 截取时间窗口，或使用抓包过滤器——
而不是全量上传后在服务端过滤。以程序方式（而非通过模型）驱动 MCP 会话的客户端
没有这个上限，可以用满 100 MiB。

## 在 MCP 网关之后

目标部署形态是：由网关认证客户端，并将 MCP 代理到本服务端。这种结构的两个特性
决定了上传能提供什么保证，在对外开放该功能前都值得了解。

**服务端看不到任何调用方身份。** 遵循 MCP 授权规范的网关不得把客户端令牌转发给上游，
因此本服务端只会收到网关自己的凭据。没有任何用户、租户或 claim 可供绑定上传。

**会话不会保持。** 代理型网关通常为每个请求新建一个上游会话，因此上传调用与随后的
分析调用会落在不同的 MCP 会话上。以会话为键的存储会在两者之间丢失文件。

剩下的就是一种能力凭证（capability）：`upload://` 句柄是 128 位随机令牌，
持有它即是授权。任何能访问服务端**并且**知道句柄的人都能读取该抓包。
这弱于按用户的访问控制，也是服务端凭自身所能提供的最强保证。

实践上这意味着：

- **除网关外，服务端不应可达。** 句柄不能替代网关的认证；它只能防止一个客户端
  猜到另一个客户端的上传。
- **上传在同一网关的各客户端之间共享。** `wireshark_list_uploads` 会列出所有存活的上传。
  不要让互不信任的多个租户共用一个服务端实例——每个信任域部署一个。
- **保持较短的 TTL。** 这是句柄一旦泄露后仍然可用时间的主要上界。
- **磁盘是共享资源。** 大小上限是按单次上传计算的，不是按目录。使用带独立配额的
  专用卷或 tmpfs，可避免繁忙会话占满宿主机磁盘。

## 会做哪些校验

上传在可被分析之前会经过校验：

- **magic number。** 内容必须以 pcap 或 pcapng 签名开头。分片上传在拼装完成后校验一次。
- **可读性。** `capinfos` 必须能打开最终文件。校验失败的上传会被删除，而不是留给
  第一次分析调用去踩。未安装 `capinfos` 时跳过该检查。
- **大小。** 每一片都按累计总量校验，因此分片上传无法通过拆分绕过上限。
- **文件名。** 仅作为标签使用；存储路径由句柄派生，绝不来自调用方输入。

上传文件以 `0600` 写入 `0700` 目录，服务端路径不会返回给调用方。

## 容器示例

```sh
docker run --rm -p 127.0.0.1:8080:8080 \
  --tmpfs /uploads:rw,size=512m,mode=0700 \
  -v "$PWD/captures:/captures:ro" \
  -e WIRESHARK_MCP_ALLOWED_DIRS=/captures \
  -e WIRESHARK_MCP_UPLOAD_DIR=/uploads \
  -e WIRESHARK_MCP_UPLOAD_TTL=1800 \
  ghcr.io/bx33661/wireshark-mcp:3.0.0
```

tmpfs 让上传目录的容量独立于宿主机磁盘，并在容器停止时丢弃其内容。
只读的 `/captures` 挂载仍可并存——上传是新增一种抓包来源，而不是取代原有来源。
