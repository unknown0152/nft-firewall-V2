SHELL := /bin/bash
VERSION ?= 2.0.1
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -s -w -buildid= -X github.com/unknown0152/nft-firewall-v2/internal/version.Version=$(VERSION) -X github.com/unknown0152/nft-firewall-v2/internal/version.Commit=$(COMMIT) -X github.com/unknown0152/nft-firewall-v2/internal/version.Date=$(BUILD_DATE)

.PHONY: all fmt fmt-check test race vet static vuln security check build release deb clean namespace
all: check build
fmt:
	gofmt -w ./cmd ./internal ./scripts/release-manifest.go
fmt-check:
	test -z "$$(gofmt -l ./cmd ./internal ./scripts/release-manifest.go)"
test:
	go test ./...
race:
	go test -race ./...
vet:
	go vet ./...
static:
	staticcheck ./...
vuln:
	govulncheck ./...
security:
	gosec -quiet -exclude-generated -exclude=G104,G204,G304,G302 ./...
check: fmt-check test race vet
build:
	mkdir -p dist
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags '$(LDFLAGS)' -o dist/nftfw ./cmd/nftfw
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags '$(LDFLAGS)' -o dist/nftfwd ./cmd/nftfwd
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags '$(LDFLAGS)' -o dist/nftfw-web ./cmd/nftfw-web
release:
	mkdir -p dist
	for arch in amd64 arm64; do \
		for bin in nftfw nftfwd nftfw-web; do \
			CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -buildvcs=false -trimpath -ldflags '$(LDFLAGS)' -o dist/$$bin-linux-$$arch ./cmd/$$bin; \
		done; \
	done
	cd dist && sha256sum nftfw*-linux-* > SHA256SUMS
deb: release
	./scripts/build-deb.sh $(VERSION) amd64
	./scripts/build-deb.sh $(VERSION) arm64
namespace:
	sudo ./tests/namespaces/run.sh
clean:
	rm -rf dist
