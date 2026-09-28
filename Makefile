SHELL := /bin/sh

BINARY := bin/ulpf
VERSION ?= dev
COMMIT ?= $$(git rev-parse --short HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= $$(date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(BUILD_DATE)

.PHONY: build check fmt test test-race vet clean

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/ulpf

fmt:
	@test -z "$$(gofmt -l .)" || { gofmt -d .; exit 1; }

vet:
	go vet ./...

test:
	go test ./...

test-race:
	go test -race ./...

check: fmt vet test

clean:
	rm -rf bin coverage.out coverage.html
