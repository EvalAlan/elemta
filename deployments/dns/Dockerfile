# The dev stack's caching, DNSSEC-validating resolver (see unbound.conf).
#
# Built locally rather than pulled: it is three lines on top of Alpine, and a
# third-party unbound image would be one more thing to trust and pin.
FROM alpine:3.22
RUN apk add --no-cache unbound dnssec-root \
 && cp /usr/share/dnssec-root/trusted-key.key /etc/unbound/root.key
CMD ["unbound", "-d", "-c", "/etc/unbound/unbound.conf"]
