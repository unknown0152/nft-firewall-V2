SHELL := /bin/bash
VERSION ?= 2.0.0
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -s -w -X github.com/unknown0152/nft-firewall-v2/internal/version.Version=$(VERSION) -X github.com/unknown0152/nft-firewall-v2/internal/version.Commit=$(COMMIT) -X github.com/unknown0152/nft-firewall-v2/internal/version.Date=$(BUILD_DATE)

.PHONY: all fmt fmt-check test race vet check build release clean namespace
all: check build
fmt:
	gofmt -w ./cmd ./internal
fmt-check:
	test -z "$$(gofmt -l ./cmd ./internal)"
test:
	go test ./...
race:
	go test -race ./...
vet:
	go vet ./...
check: fmt-check test race vet
build:
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/nftfw ./cmd/nftfw
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/nftfwd ./cmd/nftfwd
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/nftfw-web ./cmd/nftfw-web
release:
	mkdir -p dist
	for arch in amd64 arm64; do \
		for bin in nftfw nftfwd nftfw-web; do \
			CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$$bin-linux-$$arch ./cmd/$$bin; \
		done; \
	done
	cd dist && sha256sum nftfw*-linux-* > SHA256SUMS
namespace:
	sudo ./tests/namespaces/run.sh
clean:
	rm -rf dist
