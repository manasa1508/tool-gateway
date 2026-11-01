# MCP compatibility contract

This implementation intentionally supports the 2025-11-25 protocol profile.
That version uses an initialization handshake and per-session capabilities. The
2026-07-28 revision uses per-request metadata and discovery instead. A future
adapter must implement and test those semantics explicitly; it must not infer
authorization state from an old handshake.

| Feature | Status |
| --- | --- |
| JSON-RPC 2.0 individual UTF-8 messages | Supported; duplicate keys, batches, null/noninteger IDs and excess depth rejected |
| `initialize`, `notifications/initialized`, `ping` | Supported for 2025-11-25 |
| `tools/list`, `tools/call` | Supported, filtered and reconstructed |
| Paginated upstream registries | Collected atomically within hard bounds; host receives one complete bounded list |
| `resources/list`, `resources/read` | Exact operator-reviewed URI contracts, aliased URI, text results only |
| `prompts/list`, `prompts/get` | Reviewed prompt contracts and declared string arguments; text messages only |
| stdio downstream/upstream | Newline JSON framing; frame limit; no raw stderr forwarding |
| Streamable HTTP downstream | POST JSON responses; 202 for notifications; DELETE for termination; GET returns 405 |
| Streamable HTTP upstream | Fixed HTTPS endpoint; JSON or bounded SSE response consumption; separate auth/session |
| Tool/list change notifications | Dropped; non-strict clients may explicitly re-list; no advertised subscription capability |
| Text and embedded text resources in tool output | Reconstructed as plain text |
| Structured JSON tool output | Entire result scanned; structured JSON retained; no output-schema guarantee |
| Images, audio, blobs, resource links, icons, arbitrary metadata | Dropped; no-supported-content responses rejected |
| Reverse requests (sampling/roots/elicitation) | Denied or closed; never forwarded to host/model |
| Progress/cancellation notifications and subscriptions | Not forwarded; request deadlines and task cancellation are implemented locally |
| Tasks, completions, resource templates, experimental extensions | Disabled |
| Legacy HTTP+SSE | Disabled |
| 2026-07-28 modern profile and `server/discover` | Explicit unsupported-version response naming 2025-11-25 |
| Windows | Not supported; durable journal locking targets Linux/macOS/Unix |

No transparent, unrestricted MCP proxy compatibility is claimed. A strict tool
schema subset also means that some legitimate servers require schema changes or
a separately reviewed adapter. See `docs/policy.md` before enrollment.

Primary specifications:

* [2025-11-25 transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
* [2025-11-25 tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
* [2026-07-28 versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
