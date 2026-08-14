FROM --platform=$BUILDPLATFORM golang:1.26.6-alpine3.24@sha256:af8d6740070b8906d12eae1c3e3ea0957fb63f492051ea05e354c38ef9fe88df AS go-builder

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

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS bin-builder

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates wget jq

ARG TARGETARCH
ARG MIHOMO_VERSION
ARG WGCF_VERSION
ARG MIHOMO_CPU_VARIANT=v1

RUN WGCF_RELEASE_VERSION="${WGCF_VERSION#v}"; \
    if [ -z "${WGCF_RELEASE_VERSION}" ]; then \
        WGCF_RELEASE_VERSION="$(wget -q -O - "https://api.github.com/repos/ViRb3/wgcf/releases/latest" | jq -er '.tag_name | ltrimstr("v")')"; \
    fi; \
    case "${WGCF_RELEASE_VERSION}" in \
        ""|*[!0-9A-Za-z._-]*) echo "ERROR: invalid wgcf version" >&2; exit 1 ;; \
    esac; \
    case "${TARGETARCH}" in \
        amd64|arm64) ;; \
        *) echo "ERROR: unsupported target architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    WGCF_FILE="wgcf_${WGCF_RELEASE_VERSION}_linux_${TARGETARCH}"; \
    WGCF_DIGEST="$(wget -q -O - "https://api.github.com/repos/ViRb3/wgcf/releases/tags/v${WGCF_RELEASE_VERSION}" | jq -er --arg file "${WGCF_FILE}" '[.assets[] | select(.name == $file) | .digest] | if length == 1 then .[0] else error("expected exactly one matching asset digest") end')"; \
    WGCF_SHA256="${WGCF_DIGEST#sha256:}"; \
    printf '%s\n' "${WGCF_SHA256}" | grep -Eq '^[a-f0-9]{64}$' || { echo "ERROR: invalid wgcf SHA-256 digest" >&2; exit 1; }; \
    wget -q -O /tmp/wgcf "https://github.com/ViRb3/wgcf/releases/download/v${WGCF_RELEASE_VERSION}/${WGCF_FILE}"; \
    printf '%s  %s\n' "${WGCF_SHA256}" /tmp/wgcf | sha256sum -c -; \
    chmod 0555 /tmp/wgcf

RUN MIHOMO_RELEASE_VERSION="${MIHOMO_VERSION#v}"; \
    if [ -z "${MIHOMO_RELEASE_VERSION}" ]; then \
        MIHOMO_RELEASE_VERSION="$(wget -q -O - "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest" | jq -er '.tag_name | ltrimstr("v")')"; \
    fi; \
    case "${MIHOMO_RELEASE_VERSION}" in \
        ""|*[!0-9A-Za-z._-]*) echo "ERROR: invalid mihomo version" >&2; exit 1 ;; \
    esac; \
    case "${TARGETARCH}" in \
        amd64) \
            case "${MIHOMO_CPU_VARIANT}" in \
                v1|v2|v3) ;; \
                *) echo "ERROR: invalid mihomo CPU variant: ${MIHOMO_CPU_VARIANT}" >&2; exit 1 ;; \
            esac; \
            MIHOMO_FILE="mihomo-linux-amd64-${MIHOMO_CPU_VARIANT}-v${MIHOMO_RELEASE_VERSION}.gz" \
            ;; \
        arm64) MIHOMO_FILE="mihomo-linux-arm64-v${MIHOMO_RELEASE_VERSION}.gz" ;; \
        *) echo "ERROR: unsupported target architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    MIHOMO_DIGEST="$(wget -q -O - "https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/v${MIHOMO_RELEASE_VERSION}" | jq -er --arg file "${MIHOMO_FILE}" '[.assets[] | select(.name == $file) | .digest] | if length == 1 then .[0] else error("expected exactly one matching asset digest") end')"; \
    MIHOMO_SHA256="${MIHOMO_DIGEST#sha256:}"; \
    printf '%s\n' "${MIHOMO_SHA256}" | grep -Eq '^[a-f0-9]{64}$' || { echo "ERROR: invalid mihomo SHA-256 digest" >&2; exit 1; }; \
    wget -q -O /tmp/mihomo.gz "https://github.com/MetaCubeX/mihomo/releases/download/v${MIHOMO_RELEASE_VERSION}/${MIHOMO_FILE}"; \
    printf '%s  %s\n' "${MIHOMO_SHA256}" /tmp/mihomo.gz | sha256sum -c -; \
    gunzip /tmp/mihomo.gz; \
    chmod 0555 /tmp/mihomo

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

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
COPY --from=bin-builder /tmp/wgcf /usr/local/bin/wgcf
COPY --from=bin-builder /tmp/mihomo /usr/local/bin/mihomo

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
