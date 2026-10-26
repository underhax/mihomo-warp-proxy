FROM virb3/wgcf:2.3.1@sha256:49d6409a14fea1c3c30e306b1aa9bbe7847a7b4fe93899166dd16954c8eee400 AS wgcf
FROM metacubex/mihomo:v1.19.33@sha256:9211361a3ed85305383288d38c05e85862d6d5a590c10007c37fc059cca82e9c AS mihomo
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.24@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS go-builder

ARG TARGETOS
ARG TARGETARCH
ARG MIHOMO_VERSION=dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=${MIHOMO_VERSION}" \
    -trimpath \
    -o /entrypoint \
    ./cmd/entrypoint/

FROM alpine:3.24.2@sha256:31b6477333eb8257db9e5d7c3a7264fd0467928756f0bbcc27d35bea5d28cdbd

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

LABEL org.opencontainers.image.source="https://github.com/underhax/mihomo-warp-proxy" \
      org.opencontainers.image.description="Cloudflare WARP SOCKS5/HTTP(S) proxy via mihomo (Clash Meta)" \
      maintainer="underhax"

# hadolint ignore=DL3018
RUN apk add --no-cache \
        su-exec \
        tini \
        curl \
        tzdata \
    && addgroup -g 911 -S mihomo \
    && adduser -u 911 -D -S -G mihomo mihomo

COPY --from=go-builder /entrypoint /usr/local/bin/entrypoint
COPY --from=wgcf /wgcf /usr/local/bin/wgcf
COPY --from=mihomo /mihomo /usr/local/bin/mihomo

RUN chmod 0555 /usr/local/bin/entrypoint \
               /usr/local/bin/mihomo \
               /usr/local/bin/wgcf \
    && mkdir -p /app/mihomo /app/wgcf /app/logs \
    && chown -R 911:911 /app \
    && chmod 0750 /app/mihomo /app/wgcf

ENV PROXY_UID=911 \
    PROXY_GID=911 \
    MULTI_USER_MODE=true \
    PROXY_PORT=7890 \
    PROXY_LOG_LEVEL=error \
    SCRIPT_LOG_LEVEL=ERROR

WORKDIR /app
EXPOSE 7890

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint"]
