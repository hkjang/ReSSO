.PHONY: lint test build web image release

VERSION ?= v0.4.1-dev
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# The package list mirrors what CI lints. CI runs golangci-lint before the
# frontend install, so its ./... covers exactly these; locally web/node_modules
# exists and ships a vendored Go package that must not be linted.
GO_PACKAGES = ./cmd/... ./internal/... ./webui/...

lint:
	golangci-lint run $(GO_PACKAGES)
	govulncheck $(GO_PACKAGES)
	cd web && npm run lint

test:
	go test -race ./...
	go vet ./...
	cd web && npm run test && npm run build

web:
	cd web && npm run build

build: web
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/hkjang/ReSSO/internal/version.Version=$(VERSION) -X github.com/hkjang/ReSSO/internal/version.Commit=$(COMMIT) -X github.com/hkjang/ReSSO/internal/version.BuildTime=$(BUILD_TIME)" -o build/resso ./cmd/resso

image:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_TIME=$(BUILD_TIME) -t resso:$(VERSION) .

release:
	./scripts/release-image.sh $(VERSION)
