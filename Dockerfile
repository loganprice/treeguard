# syntax=docker/dockerfile:1

# ------------------------------------------------------------------------------
# Build Stage
# ------------------------------------------------------------------------------
FROM golang:alpine AS builder

# Install build dependencies for Cgo compilation (Tree-sitter)
RUN apk add --no-cache build-base git

WORKDIR /build

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source tree
COPY . .

# Dynamic build metadata
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

# Build statically linked binary with Cgo enabled
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags "-s -w -X github.com/loganprice/treeguard/internal/version.Version=${VERSION} -X github.com/loganprice/treeguard/internal/version.Commit=${COMMIT} -X github.com/loganprice/treeguard/internal/version.Date=${DATE} -extldflags '-static'" \
    -tags netgo,osusergo \
    -v -o /build/treeguard ./cmd/treeguard

# ------------------------------------------------------------------------------
# Runtime Stage
# ------------------------------------------------------------------------------
FROM alpine:3.21

# Install CA certificates and git for repository diff analysis
RUN apk add --no-cache ca-certificates git

# Create unprivileged application user
RUN addgroup -S -g 10001 treeguard && \
    adduser -S -u 10001 -G treeguard -h /home/treeguard treeguard

# Install TreeGuard binary and bundled security rules
COPY --from=builder /build/treeguard /usr/local/bin/treeguard
COPY rules /rules
RUN chown -R treeguard:treeguard /rules

USER treeguard
WORKDIR /workspace

ENTRYPOINT ["treeguard"]
CMD ["--help"]
