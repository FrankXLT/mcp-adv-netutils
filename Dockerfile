# Stage 1: Build binary
FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/mcp-adv-netutils main.go

# Stage 2: Runtime image with traceroute & network utilities + supergateway
FROM ghcr.io/supercorp-ai/supergateway:latest

LABEL org.opencontainers.image.source="https://github.com/FrankXLT/mcp-adv-netutils"
LABEL org.opencontainers.image.description="Advanced Network Utilities MCP Server (IEEE OUI, Traceroute, Port Scan, DNS, WOL)"
LABEL org.opencontainers.image.licenses="MIT"

USER root
RUN apk add --no-cache \
    ca-certificates \
    iputils \
    iproute2 \
    traceroute \
    bind-tools

WORKDIR /app
COPY --from=builder /bin/mcp-adv-netutils /usr/local/bin/mcp-adv-netutils

# Expose default SSE/StreamableHTTP port
EXPOSE 8000

ENTRYPOINT ["supergateway"]
CMD ["--port", "8000", "--cors", "--outputTransport", "streamableHttp", "--streamableHttpPath", "/sse", "--stateful", "--stdio", "/usr/local/bin/mcp-adv-netutils"]
