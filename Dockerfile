# Stage 1: Build static pure-Go binary
FROM golang:1.26-alpine AS builder

ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -trimpath \
    -tags netgo \
    -o /bin/mcp-adv-netutils \
    .

# Stage 2: Minimal Alpine runtime (< 30 MB, zero Node.js / supergateway)
FROM alpine:3.21

LABEL io.modelcontextprotocol.server.name="io.github.FrankXLT/mcp-adv-netutils"
LABEL org.opencontainers.image.source="https://github.com/FrankXLT/mcp-adv-netutils"
LABEL org.opencontainers.image.description="Advanced Network Utilities MCP Server, Cron Monitor & Operator Studio"
LABEL org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache \
        ca-certificates \
        traceroute \
        tzdata && \
    addgroup -g 1000 -S netutils && \
    adduser -u 1000 -S -G netutils -H -s /sbin/nologin netutils && \
    mkdir -p /data && \
    chown -R 1000:1000 /data && \
    chmod 0755 /data

COPY --chmod=0644 watchlist.yaml /app/watchlist.yaml
RUN --mount=type=bind,from=builder,source=/bin/mcp-adv-netutils,target=/tmp/mcp-adv-netutils \
    apk add --no-cache --virtual .cap libcap && \
    cp /tmp/mcp-adv-netutils /usr/local/bin/mcp-adv-netutils && \
    chmod 0755 /usr/local/bin/mcp-adv-netutils && \
    setcap cap_net_raw+ep /usr/local/bin/mcp-adv-netutils && \
    apk del --no-cache .cap

USER netutils
WORKDIR /data
VOLUME ["/data"]

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/mcp-adv-netutils"]
CMD ["--http", "--http-addr=:8000", "--data-dir=/data"]
