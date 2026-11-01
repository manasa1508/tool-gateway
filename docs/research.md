# Design sources and differentiation

Research was checked during implementation against primary sources. Indexed
Kevlar GitHub documentation was accessible, but the live GitHub repository API
returned 404 at publication time; its present availability is not assumed. This is an
independent implementation inspired by published threat models and proxy use
cases, not a fork or copy of Kevlar source.

* [Ablation-Tool/Kevlar](https://github.com/Ablation-Tool/kevlar): reference use case
  for bidirectional MCP mediation, description stripping, structural schema CDR,
  registry controls, scoring modes and outbound credential checks.
* [MCP security best practices](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices):
  token-audience separation, proxy threats, SSRF and local server risks. MCP has
  security guidance; it is inaccurate to describe the specification as having no
  security provisions. It cannot guarantee that arbitrary natural-language
  content is benign, and policy remains an implementation/deployment concern.
* [OWASP MCP security cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html):
  full-definition integrity checks, least privilege and separate server secrets.
* [Pipelock](https://github.com/pipelab-org/pipelock): existing egress and MCP
  security work includes taint escalation, behavioral contracts and evidence
  receipts. Those categories are not presented here as new inventions.
* [Provenance-bound capability-envelope pinning](https://www.tdcommons.org/dpubs_series/10604/):
  published prior art on identity-bound tool-surface pinning and reapproval.
* [Go security practices](https://go.dev/doc/security/best-practices): race
  detection, fuzzing and vulnerability checking informed the validation workflow.

The product choices implemented here are the combination of operator-authored
tool descriptions, conservative cumulative task labels, durable single-use
exact-action approvals, definition revalidation immediately before an action,
and deterministic source-bundle checks using the same scanner and policy.

Useful further work requires its own threat model: a host integration that
cryptographically binds actual model-context lifecycle to task labels; a real
2026-07-28 adapter; authenticated publisher attestation for integration bundles;
and a distributed approval/evidence store with explicit consistency guarantees.
These are future directions, not functionality claimed by this release.
