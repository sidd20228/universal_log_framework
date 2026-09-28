SHELL := /bin/sh

BINARY := bin/ulpf
VERSION ?= dev
COMMIT ?= $$(git rev-parse --short HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= $$(date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(BUILD_DATE)

.PHONY: build benchmark-dataset check fmt fuzz security-smoke test test-race vet clean

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/ulpf

benchmark-dataset:
	test -n "$(OUT)" || { printf '%s\n' 'usage: make benchmark-dataset OUT=/new/output/path'; exit 2; }
	go run ./cmd/ulpf-benchgen -out "$(OUT)"

fmt:
	@test -z "$$(gofmt -l .)" || { gofmt -d .; exit 1; }

vet:
	go vet ./...

test:
	go test ./...

test-race:
	go test -race ./...

security-smoke:
	go test ./internal/auth ./internal/ingress ./internal/interpret/re2parser ./internal/registry ./internal/securitytest -count=1 -run '^(Fuzz|TestSecurity|TestPermissionMatrix|TestLoaderRejectsTraversalAndSymlinks|TestPathologicalPatternCompletesWithoutBacktracking|TestHTTPRejectsOversizeWithoutDurableWrites|TestUDPListenerRejectsOversizeAndAccountsForTruncation)'

fuzz:
	FUZZTIME="$(or $(FUZZTIME),10s)" ./scripts/run-fuzz.sh

check: fmt vet test

clean:
	rm -rf bin coverage.out coverage.html
