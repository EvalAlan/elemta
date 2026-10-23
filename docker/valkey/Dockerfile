# Valkey 8.0.11 with the Linux socket error queue fix backported to its
# bundled hiredis (https://github.com/redis/hiredis/pull/1375). A connect-time
# ICMP error can otherwise leave Sentinel spinning at a full core after the
# TCP connection succeeds.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS builder

RUN apk add --no-cache build-base git linux-headers openssl-dev
RUN git clone --depth=1 --branch 8.0.11 https://github.com/valkey-io/valkey.git /src \
    && test "$(git -C /src rev-parse HEAD)" = 4bf1df6441949d70b38e748ffe39daaca9f6f89c
COPY hiredis-error-queue.patch /tmp/hiredis-error-queue.patch
RUN patch -d /src -p1 < /tmp/hiredis-error-queue.patch \
    && make -C /src -j4 MALLOC=libc BUILD_TLS=yes

FROM valkey/valkey:8.0.11-alpine@sha256:fd348c9b6999ef15719a1d6b43b810ee1bf2068ded2d7ab6f6dd15943841f28b
COPY --from=builder /src/src/valkey-server /usr/local/bin/valkey-server
