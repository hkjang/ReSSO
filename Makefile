.PHONY: lint test test-services test-services-stop build web image release

# Recipes run under bash with pipefail. `make test` pipes the test output
# through tee to keep a log, and read the status of that pipeline with $?,
# which under a POSIX shell is tee's — always zero. So a failing `go test`
# printed its FAIL, the recipe carried on to the next line, and the only reason
# the build ever stopped was something later failing on its own. The comment
# above that target is about a run that looks clean when it is not; the line
# under it was the clearest way to produce one.
SHELL := /bin/bash
.SHELLFLAGS := -o pipefail -c

VERSION ?= v0.6.5-dev
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# The package list mirrors what CI lints. CI runs golangci-lint before the
# frontend install, so its ./... covers exactly these; locally web/node_modules
# exists and ships a vendored Go package that must not be linted.
GO_PACKAGES = ./cmd/... ./internal/... ./webui/...

# Every frontend target below needs node_modules. Without this a fresh clone
# meets "vitest: not found" from `make test` — the command the README gives as
# the way to check your work — instead of the install it was missing. CI runs
# npm ci explicitly, so only people cloning the repository hit it. Make reruns
# the install only when the lockfile moves.
web/node_modules: web/package-lock.json web/package.json
	cd web && npm ci
	@touch $@

# govulncheck reports on the standard library of whichever Go is on PATH, not
# the one go.mod names, so it was describing the developer's machine rather
# than the artifact. That reads as false alarms when the local toolchain is
# older than the one that ships — and, worse, stays quiet when it is newer.
# The image builds on the version in the toolchain directive and CI resolves
# the same from go.mod; asking for it here makes all three agree.
lint: web/node_modules
	golangci-lint run $(GO_PACKAGES)
	GOTOOLCHAIN=auto govulncheck $(GO_PACKAGES)
	cd web && npm run lint

# A skipped test still lets `go test` print ok, and sixty of these are gated on
# services being reachable — so a run without them looks exactly like a clean
# one, right up until CI disagrees. The count is reported rather than hidden.
test: web/node_modules
	go test -race ./... 2>&1 | tee /tmp/resso-go-test.log; \
		status=$$?; \
		skipped=$$(go test ./internal/... -run 'TestIntegration|TestDirectory' -v 2>&1 | grep -c '^--- SKIP' || true); \
		if [ "$$skipped" -gt 0 ]; then \
			echo; \
			echo "$$skipped integration test(s) did not run: their services were not reachable."; \
			echo "Start them with: eval \"\$$(scripts/test-services.sh)\""; \
		fi; \
		exit $$status
	go vet ./...
	cd web && npm run test && npm run build

# Brings up PostgreSQL and the two directories the integration tests need.
test-services:
	@./scripts/test-services.sh

test-services-stop:
	@./scripts/test-services.sh --stop

web: web/node_modules
	cd web && npm run build

build: web
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/hkjang/ReSSO/internal/version.Version=$(VERSION) -X github.com/hkjang/ReSSO/internal/version.Commit=$(COMMIT) -X github.com/hkjang/ReSSO/internal/version.BuildTime=$(BUILD_TIME)" -o build/resso ./cmd/resso

image:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_TIME=$(BUILD_TIME) -t resso:$(VERSION) .

release:
	./scripts/release-image.sh $(VERSION)
