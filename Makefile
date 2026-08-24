SHELL := /bin/bash
TARGET_VERSION := $(shell sed -n '1p' RELEASE_VERSION 2>/dev/null)
VERSION ?= $(TARGET_VERSION)
COMMIT ?= $(shell git rev-parse --verify 'HEAD^{commit}' 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
DISPOSITION ?= development
NFTFW_BUILD_DISPOSITION ?= $(DISPOSITION)
ARTIFACT_IDENTITY = $(VERSION)|$(COMMIT)|$(BUILD_DATE)|$(NFTFW_BUILD_DISPOSITION)
LDFLAGS = -s -w -buildid= -X github.com/unknown0152/nft-firewall-v2/internal/version.Version=$(VERSION) -X github.com/unknown0152/nft-firewall-v2/internal/version.Commit=$(COMMIT) -X github.com/unknown0152/nft-firewall-v2/internal/version.Date=$(BUILD_DATE) -X github.com/unknown0152/nft-firewall-v2/internal/version.BuildDisposition=$(NFTFW_BUILD_DISPOSITION) -X github.com/unknown0152/nft-firewall-v2/internal/version.ArtifactIdentity=$(ARTIFACT_IDENTITY)

.PHONY: all fmt fmt-check test race vet static vuln security check build release release-metadata-check deb clean namespace
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
release: release-metadata-check
	mkdir -p dist
	for arch in amd64 arm64; do \
		for bin in nftfw nftfwd nftfw-web; do \
			CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -buildvcs=false -trimpath -ldflags '$(LDFLAGS)' -o dist/$$bin-linux-$$arch ./cmd/$$bin; \
		done; \
	done
	cd dist && sha256sum nftfw*-linux-* > SHA256SUMS
release-metadata-check:
	@[[ '$(COMMIT)' =~ ^[0-9a-f]{40}$$ ]] || { echo 'release/deb builds require COMMIT to be a full 40-hex Git commit' >&2; exit 1; }
	@[[ '$(VERSION)' =~ ^[0-9]+\.[0-9]+\.[0-9]+([~+][A-Za-z0-9.]+)?$$ ]] || { echo 'release/deb builds require a valid explicit VERSION or tracked RELEASE_VERSION' >&2; exit 1; }
	@[[ '$(BUILD_DATE)' =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$$ ]] || { echo 'release/deb builds require BUILD_DATE in UTC RFC3339 form' >&2; exit 1; }
	@case '$(NFTFW_BUILD_DISPOSITION)' in development|ci|stage-r-candidate-only|release) ;; *) echo 'release/deb builds require NFTFW_BUILD_DISPOSITION=development, ci, stage-r-candidate-only, or release' >&2; exit 1 ;; esac
	@target='$(TARGET_VERSION)'; version='$(VERSION)'; commit='$(COMMIT)'; disposition='$(NFTFW_BUILD_DISPOSITION)'; \
		candidate="$$target~stage.r.$${commit:0:12}"; \
		case "$$disposition" in \
			release) [[ "$$version" == "$$target" ]] || { echo 'release disposition requires the exact tracked release version' >&2; exit 1; } ;; \
			stage-r-candidate-only) [[ "$$version" == "$$candidate" ]] || { echo 'Stage R disposition requires target~stage.r.commit12 identity' >&2; exit 1; } ;; \
			development|ci) [[ "$$version" == "$$target" || "$$version" == "$$target"+* ]] || { echo 'development/CI versions must remain bound to the tracked release target' >&2; exit 1; } ;; \
		esac
deb: release
	NFTFW_BUILD_DISPOSITION='$(NFTFW_BUILD_DISPOSITION)' ./scripts/build-deb.sh $(VERSION) amd64
	NFTFW_BUILD_DISPOSITION='$(NFTFW_BUILD_DISPOSITION)' ./scripts/build-deb.sh $(VERSION) arm64
namespace:
	sudo ./tests/namespaces/run.sh
clean:
	rm -rf dist
