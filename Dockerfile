# Declare ARG BEFORE any FROM that uses it
ARG BASE_IMAGE=alpine:latest

# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -o jin ./cmd/

# Final stage — uses the ARG declared at top
FROM ${BASE_IMAGE}

# Install ca-certificates and tzdata
RUN if command -v apt-get >/dev/null 2>&1; then \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates tzdata && \
    rm -rf /var/lib/apt/lists/*; \
    elif command -v apk >/dev/null 2>&1; then \
    apk add --no-cache ca-certificates tzdata; \
    fi

# # Create non-root user
# RUN if command -v adduser >/dev/null 2>&1; then \
#     adduser -D -s /bin/sh jinuser; \
#     elif command -v useradd >/dev/null 2>&1; then \
#     useradd -m -s /bin/sh jinuser; \
#     fi

# Copy binary
COPY --from=builder /app/jin /usr/local/bin/jin

# USER jinuser
ENTRYPOINT ["jin"]
CMD ["--help"]