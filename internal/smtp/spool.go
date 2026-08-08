package smtp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// DefaultSpoolThreshold is the point at which a message stops being held in
// memory and starts being written to a spool file.
//
// Below it the message is small enough that a heap buffer is cheaper than the
// syscalls, and the overwhelming majority of mail is well below it. Above it
// the cost of holding the message resident — multiplied by every connection
// that is mid-DATA — is what bounds how large a message the server can accept.
const DefaultSpoolThreshold int64 = 256 * 1024

// spoolFilePrefix is shared by the spool files and the orphan sweep, so that
// only files this server created are ever removed.
const spoolFilePrefix = "elemta-spool-"

// MessageSpool accumulates message data, keeping small messages on the heap and
// spilling larger ones to a file.
//
// It exists so that the size of a message the server will accept is not bounded
// by the memory it can afford to hold per connection. DATA reception is
// network-bound and slow, so without this every in-flight session holds its
// entire message resident for the duration of the transfer.
//
// The zero value is not usable; call NewMessageSpool. Close must be called on
// every exit path — it removes the backing file, and a spool that is dropped
// without closing leaks it until the next orphan sweep.
//
// A MessageSpool is not safe for concurrent use. It is owned by a single
// session for the life of one transaction.
type MessageSpool struct {
	dir       string
	threshold int64

	mu   sync.Mutex
	mem  bytes.Buffer
	file *os.File
	path string
	size int64

	closed bool
}

// NewMessageSpool returns a spool that spills into dir once the accumulated
// data exceeds threshold. A threshold of zero spills immediately; a negative
// threshold keeps everything in memory.
//
// dir should be on the same filesystem as the queue so that a completed spool
// can be renamed into place rather than copied.
func NewMessageSpool(dir string, threshold int64) *MessageSpool {
	return &MessageSpool{dir: dir, threshold: threshold}
}

// Write appends to the spool, spilling to disk if the threshold is crossed.
func (s *MessageSpool) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return 0, errors.New("spool: write after close")
	}

	if s.file == nil && s.shouldSpill(int64(len(p))) {
		if err := s.spillLocked(); err != nil {
			return 0, err
		}
	}

	var (
		n   int
		err error
	)
	if s.file != nil {
		n, err = s.file.Write(p)
	} else {
		n, err = s.mem.Write(p)
	}
	s.size += int64(n)
	return n, err
}

// shouldSpill reports whether adding n more bytes crosses the threshold.
func (s *MessageSpool) shouldSpill(n int64) bool {
	if s.threshold < 0 {
		return false
	}
	return s.size+n > s.threshold
}

// spillLocked creates the backing file and moves anything already buffered
// into it. The caller must hold s.mu.
func (s *MessageSpool) spillLocked() error {
	if s.dir == "" {
		return errors.New("spool: no spool directory configured")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("spool: create directory: %w", err)
	}

	f, err := os.CreateTemp(s.dir, spoolFilePrefix+"*")
	if err != nil {
		return fmt.Errorf("spool: create file: %w", err)
	}
	// Message data is not world-readable.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return fmt.Errorf("spool: set permissions: %w", err)
	}

	if s.mem.Len() > 0 {
		if _, err := f.Write(s.mem.Bytes()); err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			return fmt.Errorf("spool: flush buffered data: %w", err)
		}
	}
	s.mem.Reset()

	s.file = f
	s.path = f.Name()
	return nil
}

// SpillToDisk forces the spool onto disk immediately, without waiting for the
// threshold to be crossed.
//
// Used when the client has declared a SIZE that will spill anyway, so the
// server does not first grow a heap buffer up to the threshold and then copy
// it out. Calling it on a spool that is already on disk does nothing.
func (s *MessageSpool) SpillToDisk() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("spool: spill after close")
	}
	if s.file != nil {
		return nil
	}
	return s.spillLocked()
}

// Size returns the number of bytes written so far.
func (s *MessageSpool) Size() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.size
}

// OnDisk reports whether the spool has spilled to a file.
func (s *MessageSpool) OnDisk() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file != nil
}

// Path returns the backing file's path, or "" while the spool is still in
// memory. It is valid until Close.
func (s *MessageSpool) Path() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path
}

// Reader returns a reader positioned at the start of the spooled data.
//
// Callers may take several readers; each is independent. The returned reader
// must be closed, and is only valid until the spool itself is closed. Being
// seekable is what allows DKIM to hash the body in one pass and then replay it
// in a second without holding it in memory.
func (s *MessageSpool) Reader() (io.ReadSeekCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, errors.New("spool: read after close")
	}

	if s.file == nil {
		return nopSeekCloser{bytes.NewReader(s.mem.Bytes())}, nil
	}

	// Flush anything the OS has not written yet, so a reader opened on the
	// same path sees the whole message.
	if err := s.file.Sync(); err != nil {
		return nil, fmt.Errorf("spool: sync before read: %w", err)
	}

	f, err := os.Open(s.path) // #nosec G304 -- path is a temp file this spool created
	if err != nil {
		return nil, fmt.Errorf("spool: open for read: %w", err)
	}
	return f, nil
}

// Open returns a fresh reader over the spooled data, satisfying
// queue.ContentOpener so the queue can read the body more than once — once to
// settle enqueue identity, once to write it — without it being held in memory.
func (s *MessageSpool) Open() (io.ReadCloser, error) {
	return s.Reader()
}

// Bytes returns the whole message as a slice.
//
// This defeats the point of spooling for a large message, so it is only for
// callers that genuinely need the entire body at once. Prefer Reader.
func (s *MessageSpool) Bytes() ([]byte, error) {
	s.mu.Lock()
	inMemory := s.file == nil
	if inMemory && !s.closed {
		// Copy: the caller must not alias the buffer, which keeps growing.
		out := make([]byte, s.mem.Len())
		copy(out, s.mem.Bytes())
		s.mu.Unlock()
		return out, nil
	}
	s.mu.Unlock()

	r, err := s.Reader()
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return io.ReadAll(r)
}

// Close releases the spool and removes any backing file. It is safe to call
// more than once.
func (s *MessageSpool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	s.mem.Reset()

	if s.file == nil {
		return nil
	}

	closeErr := s.file.Close()
	removeErr := os.Remove(s.path)
	s.file = nil

	if removeErr != nil && !os.IsNotExist(removeErr) {
		return fmt.Errorf("spool: remove %s: %w", s.path, removeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("spool: close %s: %w", s.path, closeErr)
	}
	return nil
}

// nopSeekCloser adapts a *bytes.Reader to io.ReadSeekCloser for the in-memory
// case, so callers do not need to care which backing the spool used.
type nopSeekCloser struct {
	*bytes.Reader
}

func (nopSeekCloser) Close() error { return nil }

// SweepOrphanedSpools removes spool files left behind by a previous run.
//
// A spool is removed by its owning session on every normal exit path, but a
// crash or a kill mid-DATA leaves the file. Without a sweep those accumulate
// until they fill the queue filesystem. Returns the number removed.
func SweepOrphanedSpools(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	var removed int
	var firstErr error
	for _, e := range entries {
		if e.IsDir() || !isSpoolFileName(e.Name()) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			if firstErr == nil && !os.IsNotExist(err) {
				firstErr = err
			}
			continue
		}
		removed++
	}
	return removed, firstErr
}

func isSpoolFileName(name string) bool {
	return len(name) > len(spoolFilePrefix) && name[:len(spoolFilePrefix)] == spoolFilePrefix
}
