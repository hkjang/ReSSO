.PHONY: test build web image release

VERSION ?= v0.1.0-dev
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

test:
	go test ./...
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
