# Policy reference

Policy is JSON, version 1. Unknown fields, duplicate keys, invalid UTF-8 and
excessive nesting are rejected. `check` validates configuration without starting
an upstream. Config is immutable for the process lifetime. Restart to change it.

See `examples/policy.json` for a complete, strict, harmless demo policy. Generate a
local copy with `demo-policy` to populate the actual binary and journal paths.

## Identity, transport and limits

| Field | Meaning |
| --- | --- |
| `version` | Must be `1` |
| `mode` | `strict`, `lenient`, or `audit` |
| `listen` | Explicit host and port; defaults to `127.0.0.1:8844` |
| `token_env` | Environment variable containing the incoming HTTP bearer token, minimum 32 characters |
| `principal` | Operator-assigned workload identity for this instance, never taken from tool arguments |
| `origins` | Exact browser origins accepted if `Origin` is present; defaults to none |
| `audit_path` | Private journal path on a durable local volume |
| `approval_public_key` | Standard Base64 Ed25519 public key; required for write/approval-gated tools |

Default limits: 1 MiB message; 15 s request deadline; 64 concurrent sessions;
900 s idle session TTL; 100 tool/context calls; 8 MiB cumulative delivered output.
The validator enforces hard supported bounds. The request ID ledger is capped at
4096 IDs per task, independent of the call budget. An upstream list is capped at
16 pages, 256 entries and 1024-byte cursors; cursor cycles are rejected.

Each `servers.ID` selects exactly one transport:

```json
{
  "command": ["/absolute/path/server", "--an-argument"],
  "env": ["SERVICE_TOKEN"],
  "tools": {}
}
```

or:

```json
{
  "url": "https://mcp.example.com/mcp",
  "token_env": "SERVICE_MCP_TOKEN",
  "tools": {}
}
```

Commands use no shell, run in a fresh temporary working directory and receive
only `LANG`, a minimal `PATH`, and explicitly named environment variables. They do
not inherit `HOME` or arbitrary environment credentials. This is environment
isolation, not an OS filesystem sandbox. Standard error is discarded to avoid
uninspected payloads and secrets appearing in host logs. Provide separate,
restricted upstream diagnostics when needed.

HTTP upstream endpoints are fixed operator configuration: HTTPS only, no URL
credentials/query/fragment, no redirects, no environment proxy inheritance,
bounded headers and response bodies, and explicit gateway-owned authorization.
Gateway and upstream token environment variables must differ. Do not assign the
same underlying credential to two differently named variables.

## Tool contracts

```json
{
  "description": "Operator-reviewed description for the AI host.",
  "sha256": "64-lowercase-hex-characters-from-inspect",
  "effect": "egress",
  "produces": [],
  "accepts": ["public"],
  "require_approval": true,
  "max_calls": 3,
  "url_fields": {"destination": ["https://approved.example.com"]}
}
```

The tool map key is the upstream name. Only explicitly configured tools appear
in the host's registry. Names must be 1–64 ASCII characters matching
`[A-Za-z][A-Za-z0-9_.-]*`. A returned alias includes the operator-controlled server
identity hash, preventing bare-name collisions across servers.

`sha256` pins the **complete original definition**, not just its schema or
description. Mandatory in strict mode; enforced whenever present in other modes.
Review original definitions before pinning. A pin certifies reviewed metadata,
not the tool implementation, workload identity or package supply chain.

`effect` is `read`, `write` or `egress`. Every write needs an exact-action approval.
Other tools can opt in with `require_approval`. Effect labels are operator assertions,
not derived from untrusted `readOnlyHint` / `destructiveHint` annotations.

`produces` adds labels after successful response delivery. A later tool must list
**all** accumulated labels in `accepts`, regardless of its effect. Labels do not
expire within the task. For example, a private-document reader produces
`confidential`; a public messaging tool with `accepts: []` then cannot execute.
This is conservative task-context information flow, not substring-based tracking.

`url_fields` requires a top-level string field and an exact HTTPS origin. It
rejects userinfo, fragments, CR/LF, backslashes, unapproved ports and lookalike
hosts. It does not inspect every URL in arbitrary nested values, follow redirects
inside the MCP server, or constrain that server's network. Use network policy too.

## Schema CDR

Supported structural keywords: `type`, `properties`, `required`,
`additionalProperties: false`, `items`, primitive `enum`, `minLength`, `maxLength`,
`minimum`, `maximum`, `minItems`, `maxItems`.

Every node needs one explicit primitive/object/array type. Object schemas become
closed. Description/title/examples/default/comment and documentation flags are
discarded. Unknown assertion keywords, references, combinators, open dictionaries,
patterns, formats and union types are rejected. Assertions are not silently
dropped. The maximum schema depth is 8, node count 512, properties per object 128,
and enum size 64. String enums use safe short identifiers rather than prose.

Argument validation enforces this same subset. Numeric validation uses bounded
exact rational comparisons rather than rounding counters or money to float64.
Numeric literals are limited to 64 characters and exponents within ±308.

## Resources and prompts

Each server can define `resources` keyed by exact upstream URI, and `prompts`
keyed by upstream prompt name. Contracts contain `description`, `sha256`,
`produces`, and, for prompts, `arguments` mapping permitted names to a required
boolean. Definitions are pinned, metadata scanned and descriptions substituted.
Resource URIs are replaced with gateway-local aliases; no arbitrary URI fetching
is exposed. Prompt arguments must be strings and match the reviewed contract.

These context reads consume the shared call budget. They are conservatively
blocked after labeled data exposure because their contracts do not declare
accepted input labels. Unsupported templates and dynamic URI patterns are disabled.

## Source artifacts

```json
{
  "artifacts": {
    "report-skill": {"kind": "skill", "sha256": "reviewed-bundle-root"}
  }
}
```

Kinds are `skill`, `plugin`, `connector`. The deterministic bundle root covers all
relative file paths, content hashes and executable flags, sorted by path. Source
inspection rejects symlinks, special files, invalid UTF-8/binary files, files over
1 MiB, bundles over 8 MiB and more than 512 files. No archive extraction or code
execution occurs. An empty bundle is rejected. The host must install the exact
immutable snapshot that passed the check; filesystem mutation after inspection is
outside this CLI preflight boundary.
