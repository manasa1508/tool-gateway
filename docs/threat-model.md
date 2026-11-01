# Threat model

## Trusted components

The operator owns policy files, installed gateway binary, deployment credentials,
approval public key, operating system and audit directory. Approval private keys
live in a separate operator environment. The host routes covered interactions
through the gateway and binds one task session to one actual agent context.

Upstream server content, definitions, annotations, results, notifications and
errors are untrusted. Model-generated calls and claims of user approval are also
untrusted. A signed ticket authorizes one exact action, not all actions in a task.

## Protected cases

* **Tool metadata poisoning:** raw prose never becomes model-visible tool prose;
  operators supply descriptions. Raw definitions are still scanned and pinned.
* **Rug pulls and shadowing:** namespaced aliases and complete-definition checks
  at discovery and immediately before calls detect advertised surface changes.
* **Credential exfiltration:** recognized credential formats are rejected in
  outgoing arguments in every mode. Incoming credential-bearing responses are
  quarantined before they reach the model.
* **Indirect injection:** bounded normalized and decoded views find known attack
  patterns; enforcement thresholds differ by mode. Unknown attacks can be missed.
* **Cross-tool laundering:** accumulating labels forbid sending data from a
  protected source into any contract that does not accept those labels.
* **Forged broad approvals:** signatures bind the exact principal/task/action/
  arguments/policy and expire within ten minutes. Nonces persist before execution.
* **Response side channels:** unknown metadata, links and media are not forwarded.
  Reverse sampling, roots and elicitation requests are never offered to the model.
* **Resource exhaustion:** bounded parsing/decoding, messages, lists, tasks, calls,
  outputs, journal capacity and request deadlines limit work and memory.
* **Audit failures:** unavailable or corrupted evidence storage fails closed;
  an unrecorded action intent cannot proceed.

## Material limits

1. This is not a complete solution to prompt injection. Regex detectors miss
   semantic, multilingual, fragmented, novel and sufficiently disguised attacks.
   Bounded decoding deliberately does not attempt arbitrary computation.
2. A stable definition hash cannot attest implementation behavior. A malicious
   server may advertise an unchanged contract while executing different code.
3. This is not a host sandbox or a network firewall for server-originated traffic.
   A process with filesystem/network access can use it without making another
   MCP call. Restrict those capabilities independently.
4. Labels cover content delivered in one gateway task. They do not track data
   from files, another model provider, an earlier task, memory outside this
   gateway, or a malicious host that resets sessions while retaining context.
5. URLs inside arbitrary data are not universally classified. A configured URL
   origin is a contract check, not DNS/SSRF containment or control over redirects
   implemented by an upstream service.
6. A gateway-local shared bearer token authenticates one configured workload.
   This release does not implement end-user OAuth, OIDC tenancy, per-user RBAC,
   certificate identity federation or automated key rotation.
7. Hash-chain consistency requires an independently retained head to detect
   complete rewrite/rollback. It proves neither authenticity of the operator nor
   completeness of mediation. Argument digests may permit guessing low-entropy
   values; protect logs even though raw payloads are absent.
8. Crash recovery cannot establish whether an arbitrary remote action committed.
   Intent is durable and approvals are spent; execution is not exactly-once.
9. Artifact scans do not establish code safety, dependency safety, publisher
   authenticity, or runtime confinement. Binary plugins and installed packages
   require separate supply-chain review. Inspect an immutable source snapshot.
10. MCP 2026-07-28, multimodal safety and arbitrary extensions are outside the
    supported protocol profile. Unknown methods fail closed.

## Expected operational boundaries

Keep the AI host's direct network and secret access appropriately constrained;
run upstreams in separate containers/users; give each server narrowly scoped
credentials; restrict network egress; persist audit on a private local volume;
retain external checkpoints; and make the real host, not the model, control task
session lifecycle. The gateway complements these controls and does not replace them.
