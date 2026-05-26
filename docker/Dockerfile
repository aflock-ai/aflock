# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build aflock binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /aflock ./cmd/aflock

# Runtime stage
FROM alpine:3.23

# Install runtime dependencies
RUN apk add --no-cache ca-certificates bash curl jq

# Copy aflock binary
COPY --from=builder /aflock /usr/local/bin/aflock

# Create aflock user
RUN adduser -D -h /home/aflock aflock

# Switch to aflock user
USER aflock
WORKDIR /workspace

# Default command
CMD ["aflock", "--help"]
