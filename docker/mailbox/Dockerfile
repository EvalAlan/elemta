FROM golang:1.27.3-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Stamped like the main image, so a mailbox replica reports its release.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X $(go list -m)/internal/version.Version=${VERSION}" -o /elemta ./cmd/elemta

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 1001 elemta && useradd -u 1001 -g elemta -d /app elemta && \
    mkdir -p /app/logs /var/lib/elemta/bodies && \
    chown -R elemta:elemta /app /var/lib/elemta
COPY --from=builder /elemta /app/elemta
WORKDIR /app
USER 1001:1001
ENTRYPOINT ["/app/elemta"]
CMD ["mailbox", "--config", "/etc/elemta/mailbox.toml"]
