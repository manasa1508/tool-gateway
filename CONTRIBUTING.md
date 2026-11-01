# Contributing

Use Go 1.27.3 or newer on Linux or macOS. Run `make check`, `make fuzz`,
`make e2e` and `go mod verify`. New policy behavior should include a boundary
test demonstrating that the rejected action never reaches an upstream.

Do not add automatic action retries, fail-open exception handling, raw payload
logging, unbounded buffering, dynamic upstream URLs, or bypasses for audit mode.
Document any change to protocol coverage or schema semantics. Detector changes
need both hostile examples and benign counterexamples. Keep test credentials
synthetic and construct token-shaped examples programmatically.

The approval signing key stays outside the gateway runtime. Single-writer audit
ordering and nonce persistence are part of the security boundary. Changes to
either require restart and concurrency tests.
