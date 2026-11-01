GO ?= go

.PHONY: build test vet check fuzz e2e clean
build:
	$(GO) build -trimpath -ldflags='-s -w' -o bin/tool-gateway ./cmd/gateway
test:
	$(GO) test -race -coverprofile=coverage.out ./...
vet:
	$(GO) vet ./...
check: vet test
fuzz:
	$(GO) test ./internal/wire -fuzz=FuzzDecode -fuzztime=15s -parallel=2
	$(GO) test ./internal/schema -fuzz=FuzzRebuild -fuzztime=15s -parallel=2
	$(GO) test ./internal/scan -fuzz=FuzzAnalyze -fuzztime=15s -parallel=2
e2e: build
	python3 tests/e2e.py --binary bin/tool-gateway
clean:
	rm -rf bin dist coverage.out
