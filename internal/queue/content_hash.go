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

// hashSeekable digests a reader and rewinds it, so the caller can go on to
// write the same bytes.
//
// This is the shape DKIM signing needs as well: one pass to compute a digest
// over the body, a rewind, and a second pass to emit it.
func hashSeekable(r io.ReadSeeker) (string, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind before hashing: %w", err)
	}
	hash, err := ContentHashFromReader(r)
	if err != nil {
		return "", err
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind after hashing: %w", err)
	}
	return hash, nil
}

// contentSource is the body being enqueued, held either as a slice the caller
// already has or as a seekable stream that should stay on disk.
//
// Identity checks and storage both go through it, so the enqueue path reads the
// same for a small in-memory message and a large spooled one.
type contentSource struct {
	data   []byte
	reader io.ReadSeeker
	hash   string
}

// contentFromBytes wraps a body the caller already holds.
func contentFromBytes(data []byte) *contentSource {
	return &contentSource{data: data}
}

// contentFromReader wraps a body that should not be brought into memory. The
// reader must be seekable: identity is checked in one pass and the body written
// in another.
func contentFromReader(r io.ReadSeeker) *contentSource {
	return &contentSource{reader: r}
}

// Hash returns the identity digest, computing it at most once.
func (c *contentSource) Hash() (string, error) {
	if c.hash != "" {
		return c.hash, nil
	}
	if c.reader != nil {
		h, err := hashSeekable(c.reader)
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
	if c.data != nil || c.reader == nil {
		return c.data, nil
	}
	if _, err := c.reader.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind before read: %w", err)
	}
	data, err := io.ReadAll(c.reader)
	if err != nil {
		return nil, err
	}
	if _, err := c.reader.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind after read: %w", err)
	}
	return data, nil
}

// Reader returns the body positioned at the start, ready to be written out.
func (c *contentSource) Reader() (io.Reader, error) {
	if c.reader != nil {
		if _, err := c.reader.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("rewind before write: %w", err)
		}
		return c.reader, nil
	}
	return bytesReader(c.data), nil
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
