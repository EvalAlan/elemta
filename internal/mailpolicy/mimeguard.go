package mailpolicy

import "bytes"

// MaxMultipartContainers is how many multipart sections a message may have
// before the code that walks its MIME tree (calendar invitations at
// delivery, the Sieve body test, the webmail's reader) declines to.
//
// go-message reads a nested section through one multipart reader per
// enclosing level, so a message made of nested multipart sections costs time
// proportional to the square of its depth to walk. At about 60 bytes a level,
// a message inside the size limit can be hundreds of thousands of levels
// deep: a 583 KiB one took 14 seconds to walk, and one near the size limit
// takes hours. Real mail has a handful of multipart sections; a digest of
// forwarded messages may have a few dozen.
const MaxMultipartContainers = 100

var multipartToken = []byte("multipart/")

// MIMETooComplex reports whether raw has more multipart sections than
// MaxMultipartContainers, in one linear pass, so callers can decline to walk
// it before the walk itself becomes the problem.
//
// It counts "multipart/" anywhere in the message, case-insensitively. That
// never undercounts: go-message doesn't apply a Content-Transfer-Encoding to
// a multipart section and doesn't descend into attached messages, so every
// multipart header it would walk appears literally in raw. It can overcount
// (the word in a body, or in an attached message), which only means a very
// unusual message is shown more plainly.
func MIMETooComplex(raw []byte) bool {
	n := 0
	for i := 0; i+len(multipartToken) <= len(raw); {
		j := bytes.IndexByte(raw[i:], '/')
		if j < 0 {
			return false
		}
		slash := i + j
		if slash >= len("multipart") && bytes.EqualFold(raw[slash-len("multipart"):slash+1], multipartToken) {
			if n++; n > MaxMultipartContainers {
				return true
			}
		}
		i = slash + 1
	}
	return false
}
