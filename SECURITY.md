# Security policy

This is a new security-sensitive implementation. Version 0.1 has automated
adversarial and integration tests, but has not received an independent security
audit. A clean scanner verdict is not a proof that content is safe.

Please report vulnerabilities through this repository's GitHub private
vulnerability reporting channel. Include the affected commit, transport, mode,
minimal synthetic reproduction and expected boundary. Do not include live tokens,
customer data or exploit payloads targeting third parties in public issues.

Only the latest release on the default branch is maintained. Updates to detector
rules and dependency versions require rerunning the adversarial corpus and
bounded fuzz tests. See `docs/threat-model.md` for the precise enforcement scope.
