# Stage 1: Build binary
FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/mcp-adv-netutils main.go

# Stage 2: Runtime image with traceroute & network utilities
FROM alpine:3.21

RUN apk add --no-cache \
    ca-certificates \
    iputils \
    iproute2 \
    traceroute \
    bind-tools

WORKDIR /app
COPY --from=builder /bin/mcp-adv-netutils /usr/local/bin/mcp-adv-netutils

# Expose default SSE port
EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/mcp-adv-netutils"]
CMD ["-sse", "-sse-port", "8000"]
