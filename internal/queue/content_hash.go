package queue

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// contentHashPrefix identifies the digest algorithm, so a future change can be
// told apart from the current one rather than silently compared against it.
const contentHashPrefix = "sha256:"

// ContentHash returns the identity digest for a message body.
//
// Enqueue idempotency used to be decided by comparing whole bodies, which
// meant every check held two full messages in memory. A digest lets the same
// decision be made from a fixed-size value, so the body can stay on disk.
func ContentHash(content []byte) string {
	sum := sha256.Sum256(content)
	return contentHashPrefix + hex.EncodeToString(sum[:])
}

// ContentHashFromReader computes the identity digest by streaming, without
// holding the body in memory.
func ContentHashFromReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("hash message content: %w", err)
	}
	return contentHashPrefix + hex.EncodeToString(h.Sum(nil)), nil
}

// ContentHashOfFile digests a file on disk without reading it into memory.
func ContentHashOfFile(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- caller supplies a queue-owned path
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	return ContentHashFromReader(f)
}

// ContentOpener returns a fresh reader over a message body.
//
// Identity is settled in one pass over the body and the body written in
// another, so the source has to be readable twice. An opener expresses that
// more simply than a seeker, and composes: a body that is a header prefix
// followed by a spool file is one call to io.MultiReader, which is not
// seekable but is trivially re-openable.
//
// The caller closes each reader it is given.
type ContentOpener func() (io.ReadCloser, error)

// OpenerForBytes adapts an in-memory body to a ContentOpener.
func OpenerForBytes(data []byte) ContentOpener {
	return func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
}

// contentSource is the body being enqueued, held either as a slice the caller
// already has or as a seekable stream that should stay on disk.
//
// Identity checks and storage both go through it, so the enqueue path reads the
// same for a small in-memory message and a large spooled one.
type contentSource struct {
	data []byte
	open ContentOpener
	hash string
}

// contentFromBytes wraps a body the caller already holds.
func contentFromBytes(data []byte) *contentSource {
	return &contentSource{data: data}
}

// contentFromOpener wraps a body that should not be brought into memory.
func contentFromOpener(open ContentOpener) *contentSource {
	return &contentSource{open: open}
}

// Hash returns the identity digest, computing it at most once.
func (c *contentSource) Hash() (string, error) {
	if c.hash != "" {
		return c.hash, nil
	}
	if c.open != nil {
		r, err := c.open()
		if err != nil {
			return "", err
		}
		defer func() { _ = r.Close() }()
		h, err := ContentHashFromReader(r)
		if err != nil {
			return "", err
		}
		c.hash = h
		return c.hash, nil
	}
	c.hash = ContentHash(c.data)
	return c.hash, nil
}

// Bytes returns the body as a slice.
//
// For a streamed source this defeats the point of streaming, so it is only used
// on the legacy path where a tombstone predates content hashes and identity can
// only be settled by comparing bodies.
func (c *contentSource) Bytes() ([]byte, error) {
	if c.open == nil {
		return c.data, nil
	}
	r, err := c.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return io.ReadAll(r)
}

// Reader returns a fresh reader over the body, ready to be written out. The
// caller closes it.
func (c *contentSource) Reader() (io.ReadCloser, error) {
	if c.open != nil {
		return c.open()
	}
	return io.NopCloser(bytes.NewReader(c.data)), nil
}
