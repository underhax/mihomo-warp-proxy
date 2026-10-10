FROM virb3/wgcf:2.3.0@sha256:eaf968a478cca813285a36aaaaa5b036ddce8d6671be1ba71e3e3281045201f0 AS wgcf
FROM metacubex/mihomo:v1.19.32@sha256:bac1a74de365ea59270ba134016762c6be05654d55246518de256113bd1c225e AS mihomo
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine3.24@sha256:85dc1069ac644ea3c527b177303a406eb3358192816cd7f9e5848eb658851673 AS go-builder

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
