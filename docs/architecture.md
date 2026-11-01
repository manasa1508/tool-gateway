# Architecture and stack decision

The gateway is a protocol enforcement service, not a CRUD application. Go is a
good fit because the critical work is bounded parsing, concurrent I/O, subprocess
management, cryptographic verification and durable evidence writes.

## Why Go

| Option | Assessment for this implementation |
| --- | --- |
| Go | Memory-safe application code without `unsafe`, native cancellation and concurrency, mature standard HTTP/TLS/process/crypto libraries, RE2 regular expressions, static deployment binary, race detector and built-in fuzzing |
| Rust + Tokio | Strong memory/resource control and attractive for a future WASM scanner; more lifetime/asynchronous integration complexity for this first transport-heavy implementation |
| TypeScript / Node | Excellent MCP ecosystem and useful host SDK candidate; runtime/package surface and synchronous-regex scheduling make isolation and latency management more involved |
| Python / FastAPI | Convenient control-plane development; an ASGI web framework contributes little to a stdio proxy, and multi-process deployment complicates task state and one-use approvals |

Go is not assumed to be universally fastest. The implementation prioritizes a
small auditable dependency surface and predictable failure behavior. The only
runtime dependency is the official `golang.org/x/text` Unicode implementation.
No detector depends on a remote model or external API being available.

## Components

* `internal/wire`: strict JSON parsing, duplicate-key rejection, bounded nesting,
  deterministic project-specific hashing and JSON-RPC envelopes.
* `internal/policy`: immutable, validated operator contracts and operational limits.
* `internal/schema`: reconstruct a restricted structural schema; validate arguments.
* `internal/scan`: weighted detector rules, normalization and bounded decoded views.
* `internal/approval`: offline-issued Ed25519 exact-action capability tickets.
* `internal/audit`: locked, bounded, fsync-backed hash chain and consumed nonces.
* `internal/transport`: isolated-environment stdio processes and fixed HTTPS clients.
* `internal/gateway`: per-task state, capability registry and shared bidirectional path.
* `internal/artifact`: deterministic source manifests and preflight policy checks.
* `cmd/gateway`: executable and operator commands; no administrative mutation API.

## Action path and failure semantics

1. Authenticate HTTP access; bind a fresh random task ID to the configured principal.
2. Accept a supported protocol request, a unique ID and a bounded parameter object.
3. Resolve a server-qualified alias from the approved registry.
4. Validate arguments against the reconstructed schema; scan for credentials and
   injection; enforce exact URL origins, all accumulated labels and call budgets.
5. For sensitive actions, verify the offline signature and all action bindings.
6. Atomically persist a call intent and consume its nonce, then fsync.
7. Fetch and verify the complete raw advertised definition again before execution.
8. Invoke once; scan the complete response, reconstruct supported content, fsync a
   delivery event, add the contract's data labels and return the result.

Steps 6–8 cannot form a distributed transaction with an arbitrary MCP server. A
crash after execution can leave an unknown outcome. A timeout kills a local
upstream or closes a remote circuit. The gateway does not retry automatically;
operators reconcile the original operation before issuing a new approval.

## Concurrency and scale

Tasks run concurrently; each task has a non-queued execution gate. A concurrent
request to a busy task gets an explicit error without execution. This establishes
a deterministic order for exposure labels, budgets and action approvals. Multiple
upstreams are initialized in stable order and have separate identities.

Task state and subprocesses live on one instance. Use sticky routing and one
private journal volume per replica; unknown task IDs return 404. Restarted
instances require new sessions, preventing resumption from incomplete security
state. The journal is intentionally single-writer and synchronously durable.
Adding a distributed journal is a separate consistency design, not a flag that
can safely be enabled on shared storage.

The current principal model is one workload identity per gateway instance. Deploy
separate instances/policies for tenants or users. It is not a multi-tenant OAuth
authorization server. An ingress can supply TLS and workload access controls,
but never remove the gateway's bearer authentication.

## Hashes and trust

The canonical form is Go `encoding/json` serialization with sorted map keys and
preserved `json.Number` spelling. It is **not RFC 8785**. Reordering object keys
does not change a pin; changing number spellings or array order may. Full raw
definitions include descriptions, schemas, annotations and extensions, so hidden
metadata changes invalidate their pins even though they are not forwarded.

Hash chains show internal consistency. Independently retained heads detect
replacement/truncation relative to the checkpoint. They do not establish an
authenticated timestamp, prove every action was mediated, or stop an operator
with full host access from replacing the entire deployment.
