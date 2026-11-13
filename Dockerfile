FROM virb3/wgcf:2.3.1@sha256:49d6409a14fea1c3c30e306b1aa9bbe7847a7b4fe93899166dd16954c8eee400 AS wgcf
FROM metacubex/mihomo:v1.19.34@sha256:4c2495d705f152897a58eac410350f243835fd01ce2fe44949a571faa824d532 AS mihomo
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

ARG TARGETOS
ARG TARGETARCH
ARG MIHOMO_VERSION=dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=${MIHOMO_VERSION}" \
    -trimpath \
    -o /out/entrypoint \
    ./cmd/entrypoint/ \
    && mkdir -p /out/app/mihomo \
                /out/app/wgcf \
                /out/tmp \
                /out/run \
                /out/etc/ssl/certs \
    && cp /etc/ssl/certs/ca-certificates.crt /out/etc/ssl/certs/ca-certificates.crt \
    && chmod 0700 /out/app/mihomo /out/app/wgcf \
    && chmod 1777 /out/tmp /out/run \
    && chmod 0755 /out/etc /out/etc/ssl /out/etc/ssl/certs \
    && chmod 0444 /out/etc/ssl/certs/ca-certificates.crt

FROM scratch

ENV PATH=/usr/local/bin \
    PROXY_PORT=7890 \
    PROXY_LOG_LEVEL=error \
    SCRIPT_LOG_LEVEL=ERROR

COPY --from=builder /out/etc /etc
COPY --from=builder /out/app /app
COPY --from=builder /out/tmp /tmp
COPY --from=builder /out/run /run

COPY --from=builder --chmod=0555 /out/entrypoint /usr/local/bin/entrypoint
COPY --from=wgcf --chmod=0555 /wgcf /usr/local/bin/wgcf
COPY --from=mihomo --chmod=0555 /mihomo /usr/local/bin/mihomo

VOLUME ["/app/mihomo", "/app/wgcf"]

WORKDIR /app
EXPOSE 7890

ENTRYPOINT ["/usr/local/bin/entrypoint"]
