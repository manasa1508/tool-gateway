# Validation record

Validation of the initial implementation used Go 1.27.3 on macOS arm64 (Apple M4
Pro), plus a Linux arm64 container built with the pinned official Go image.
These results describe the exercised cases, not proof that all attacks are blocked.

| Check | Result |
| --- | --- |
| `go vet ./...` | Passed |
| `go test -race -coverprofile=coverage.out ./...` | Passed; 282 cases including named subtests/fuzz seeds, 54 top-level functions, 10 packages |
| Statement coverage | 76.1% overall; approval 91.7%, schema 92.2%, gateway about 80%, scanner 83% |
| Real compiled-binary black-box test | Passed: stdio and authenticated HTTP, DLP denial, data-flow denial, audit verification, graceful shutdown |
| JSON parser fuzz target | Passed, 593,124 input executions in a bounded run |
| Schema CDR fuzz target | Passed, 744,949 input executions in a bounded run |
| Scanner fuzz target | Passed, 60,376 input executions in a bounded run |
| `govulncheck` v1.9.0 | No known vulnerabilities found in the checked dependency graph |
| Container build | Passed using a build-only host CA secret for the enterprise TLS proxy |
| Container smoke test | Version command passed as UID/GID 65532:65532 with read-only filesystem, all capabilities dropped and no-new-privileges |
| Runtime image size | 10,818,503 bytes in the tested arm64 image |

The deterministic suite includes malformed/duplicate JSON, Unicode/invisible
format/percent/Base64 injection variants, credential variants, benign examples,
schema assertions and bounds, exact numeric comparisons, description stripping,
registry pin changes, an empty frozen registry, aliases, DLP in all modes,
accumulating labels, exact-action approvals, restart/concurrent nonce replay,
audit corruption/truncation/locking, HTTP authentication/origins/session limits,
upstream malformed data/timeouts/floods/reverse requests/SSE, artifact mutations,
symlinks/binaries/size limits and CLI behavior.

A local scanner-only benchmark over approximately 10.5 KiB of ordinary text
measured about **4.60 ms/op**, 24.4 KB allocated and 8 allocations/op. This excludes
network latency, policy processing, journal fsync and adversarial decoding. It is
not an end-to-end throughput or service-level guarantee. Profile on deployment
hardware and storage before choosing concurrency and timeout values.

CI repeats race-enabled tests on Linux/macOS, bounded fuzzing on Linux, the real
binary tests, vulnerability checking and a container build. Kubernetes manifests
are provided for review; no Kubernetes cluster was deployed during this work.
No independent penetration test, security certification, distributed failover
exercise, large-scale load test or universal prompt-injection detection claim is
made.
