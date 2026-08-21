# syntax=docker/dockerfile:1.7

FROM node:22.23.0-alpine AS web-builder
WORKDIR /src
COPY web/package.json web/package-lock.json ./web/
RUN --mount=type=cache,target=/root/.npm cd web && npm ci
COPY web ./web
COPY webui ./webui
RUN cd web && npm run build

FROM golang:1.26.7-alpine AS go-builder
ARG VERSION=v0.4.0-dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY webui ./webui
COPY --from=web-builder /src/webui/dist ./webui/dist
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X github.com/hkjang/ReSSO/internal/version.Version=${VERSION} -X github.com/hkjang/ReSSO/internal/version.Commit=${COMMIT} -X github.com/hkjang/ReSSO/internal/version.BuildTime=${BUILD_TIME}" \
    -o /out/resso ./cmd/resso

FROM scratch
ARG VERSION=v0.4.0-dev
ARG COMMIT=unknown
LABEL org.opencontainers.image.title="ReSSO" \
      org.opencontainers.image.description="Offline-ready Keycloak-compatible OIDC SSO service" \
      org.opencontainers.image.source="https://github.com/hkjang/ReSSO" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.licenses="MIT"
COPY --from=go-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=go-builder /out/resso /resso
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/resso", "healthcheck"]
ENTRYPOINT ["/resso"]
