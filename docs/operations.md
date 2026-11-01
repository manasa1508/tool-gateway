# Operations and incident recovery

## Start safely

Run `check`, then a synthetic corpus in audit mode, before enrolling real data.
Review original tool/resource/prompt definitions, narrow credentials and the
actual upstream executable/container identity. Pins do not approve executable
code. Configure labels from the data's sensitivity and effects from the tool's
actual authority. Restart into strict mode with reviewed pins.

The default listener is loopback. For an external listener, terminate TLS at a
trusted ingress, keep the gateway bearer token, restrict network access and rate
limit new sessions/connections at the ingress. Browser Origins are denied unless
explicitly configured. Responses are `no-store`. No broad CORS policy is emitted.
Secrets belong in a secret manager/environment injection, never in JSON policy.

## Monitoring

* `GET /healthz`: process liveness, no authentication, no sensitive data.
* `GET /readyz`: readiness; 503 after journal failure or shutdown.
* `GET /metrics`: authenticated Prometheus text; request/denial counters and
  active-session gauge. No principal/tool/task labels or payloads in metrics.
* JSONL journal: action intents, delivered responses, policy denials, detector
  IDs/scores, task identity, policy hash and argument digest; no raw arguments,
  response text, bearer tokens or private signing keys.

Watch disk capacity, request failures, denial rates, session saturation and
upstream latency externally. Readiness measures the gateway's own ability to
enforce; it does not promise an arbitrary upstream is currently healthy.

## Persistence, limits and scaling

Use a private persistent directory owned by the gateway user. Journal files must
be regular files with owner-only permissions (normally 0600). Exclusive advisory
locking prevents two gateway processes from opening the same file. Do not use
shared filesystems with unreliable `flock`/`fsync` semantics. Audit records are
synchronously durable before actions; this intentionally adds storage latency.

A journal is capped at 256 MiB. Archive before it fills: stop/drain the instance,
retain the full verified journal and an external final head, then configure a
new private journal path and restart. The policy digest changes, tasks are new,
and old approvals cannot authorize actions in them. Never rotate by deleting a
live writer's file. Retain archived files according to your data policy.

One deployment serves one configured workload principal. Run independent policy,
token and journal instances per user/tenant. Route established HTTP sessions to
their owning replica. Replica loss returns 404 for old sessions; start a fresh
task and do not silently restore the model's previous context without its labels.
Each configured stdio server may launch one process per task: size both session
and container process/memory limits accordingly.

## Failure matrix

| Failure | Behavior | Recovery |
| --- | --- | --- |
| Audit write/fsync/capacity failure | No new calls; results withheld; readiness fails | Restore storage and restart from a verified journal |
| Corrupt/truncated journal | Startup refuses to proceed | Preserve original; investigate; retain independently anchored evidence; start a new task/journal only after reconciliation |
| Upstream timeout/disconnect | No automatic retry; local process killed or remote circuit closed | Reconcile action outcome, start a new task and issue a fresh exact-action approval if appropriate |
| Tool/context definition drift | Discovery/execution rejected | Review full new definition and code provenance, update pin and restart |
| New unapproved tools | Omitted from host registry | Explicit operator contract review |
| Concurrent request in one task | Explicit busy error; request not executed | Host serializes requests and uses a fresh ID |
| Reused request ID | Rejected, even when the original was denied | Fresh ID; do not use this to blindly retry unknown outcomes |
| Approval replay/expiry/mismatch | No action | Review and issue a fresh ticket for the exact action |
| SIGTERM/SIGINT | Cancel active calls, close upstreams, drain HTTP | Reconcile any calls already past the execution boundary |

An action can commit remotely while its response is lost or withheld. Approval
consumption is at-most-once within the journal; this is not exactly-once remote
execution. Use upstream idempotency keys when available, with contracts that
validate them, and reconcile in the upstream system.

## Source bundle installation

Materialize a reviewed source bundle into an immutable snapshot, inspect it,
compare its root against policy, then install that same snapshot. Keep gateway
policy and approval authority outside the artifact's writable area. Do not check
a mutable directory and later execute unrelated installed files. Runtime tool
calls must still go through MCP mediation; this preflight CLI alone is not a
plugin sandbox.
