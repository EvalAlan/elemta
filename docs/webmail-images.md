# Remote images in the webmail

Most marketing and notification mail loads its pictures from the sender's
servers. Loading them straight from the reader's browser tells the sender the
reader's IP address, browser and the moment the mail was opened. It also
breaks those messages in browsers that block trackers: Brave, and Firefox
with Enhanced Tracking Protection, refuse images from domains such as
LinkedIn's when they're loaded inside another site.

The webmail therefore fetches remote images itself and serves them from its
own address. This is the image proxy (`internal/webmail/imageproxy.go`).
It is on by default.

## What the reader sees

Images reach a message three ways, and all three go through the proxy: `<img>`
tags, `url()` in the message's `<style>` blocks, and `background-image` in
inline styles. LinkedIn, for example, puts each post's photo on a table cell
as a background, with a hidden `<img>` for Outlook. In inline styles, a
`background` or `background-image` value is kept only when every `url()` in
it names the proxy (or is a `data:` image) and the rest is plain colours,
gradients and keywords; a sender can't write a proxy address in themselves,
because only remote addresses are rewritten and anything else becomes
`none`.

Remote images are still blocked until the reader chooses Show images, or
turns on Settings > General > Load remote images automatically. Mail in Junk
never loads them automatically. Once images are allowed, they arrive through
the proxy, and the message frame's Content-Security-Policy allows images from
the webmail's own address only. Any address the rewrite misses fails to load
rather than reaching the sender.

The sender can still tell that a message was opened, and when, because the
proxy fetches the image at that moment. It can't tell who opened it, from
where, or with what browser. Images already in the cache aren't fetched
again at all.

## Abuse protection

A server that fetches URLs on request is a classic target, for server-side
request forgery or as a free relay. The proxy fetches an address only when
every one of these holds:

- **It is signed.** When a message is shown, each image address in it is
  rewritten to `/mail/image?u=<address>&s=<signature>`. The signature is an
  HMAC keyed from that session's own secret. Addresses typed by hand, taken
  from another session, or embedded by another site are refused before
  anything is fetched.
- **The user is signed in**, and within their limits: 10 uncached fetches a
  second sustained (150 in a burst) and 12 at once per user, 64 in flight
  across the server.
- **The destination is public.** The address is checked when the connection
  is made, after DNS and after each redirect, so a hostname that points at,
  or rebinds to, an internal address is refused. Refused ranges include
  loopback, private networks (and so the container network), link-local
  (including the cloud metadata address 169.254.169.254), shared address
  space, multicast, reserved and documentation ranges, and IPv6 prefixes
  that can wrap a private IPv4 address (NAT64, 6to4, Teredo, IPv4-mapped).
  Only `http` and `https` on ports 80 and 443 are accepted, with no
  credentials in the URL, no proxy from the environment, and at most three
  redirects.
- **It is an image.** The format is identified from the file's first bytes,
  not the sender's Content-Type. PNG, JPEG, GIF, WebP, AVIF, BMP and ICO
  pass. SVG is refused because it can contain script. Responses carry
  `X-Content-Type-Options: nosniff` and
  `Content-Security-Policy: default-src 'none'; sandbox`, so even a file
  opened on its own can't run anything.
- **It is small enough.** At most `image_max_mb` (5 MB by default), enforced
  while reading, so a false Content-Length or a compressed response can't
  exceed it. Each fetch has connect, TLS, header and overall timeouts.

Nothing about the reader is forwarded: no cookies, no Referer, and a generic
User-Agent. Failed addresses are not logged in full, because image URLs often
carry a per-recipient tracking token.

## Cache

Fetched images are kept on disk in `image_cache_dir`, up to `image_cache_mb`
(512 MB by default), for up to seven days. Once over the size, the least
recently used images are removed first. Failures are remembered for ten
minutes, so a dead host isn't asked again on every view. The cache is shared
between users, which is safe because a user only receives signed addresses
for images in their own mail. Each webmail replica keeps its own cache;
losing it only means images are fetched again.

## Settings

```toml
[webmail]
image_proxy = true      # false: browsers load images from senders directly
image_cache_dir = "/tmp/elemta-webmail-images"
image_cache_mb = 512
image_max_mb = 5
```

The webmail needs outbound HTTP and HTTPS to the internet for the proxy to
work. Where it has none, images fail to load and the message text is
unaffected.
