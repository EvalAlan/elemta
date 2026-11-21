package logging

import (
	"os"
	"sync"
)

// The log file used to grow without end. Docker already keeps and rotates
// everything on stdout, so the file exists for the admin console, which reads
// it for message traces and the Logs page. On the dev server it had reached
// 620 MB in three weeks, and the release overlay mounts /app/logs as a 64 MB
// tmpfs, which an unbounded file fills.
//
// rotatingFile keeps the file under maxLogSize by renaming it to <name>.1
// (replacing the previous one) and starting a new one, so the two together
// stay under twice that. Several processes can share one file: the MTA and
// the admin console do in the compose stack. Each checks the path every
// rotateCheckEvery bytes it writes, follows a rotation another process did,
// and rotates itself when the file is full, so the file overshoots by at most
// that much per writer.

const (
	maxLogSize       = 25 << 20
	rotateCheckEvery = 1 << 20
)

type rotatingFile struct {
	mu      sync.Mutex
	path    string
	max     int64
	f       *os.File
	written int64
}

func openRotating(path string, max int64) (*rotatingFile, error) {
	r := &rotatingFile{path: path, max: max}
	if info, err := os.Stat(path); err == nil && info.Size() >= max {
		// Left full by an older version or another process: start fresh
		// rather than adding to it.
		_ = os.Rename(path, path+".1")
	}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotatingFile) open() error {
	// #nosec G304 -- the operator's configured log file
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if r.f != nil {
		_ = r.f.Close()
	}
	r.f, r.written = f, 0
	return nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.written >= rotateCheckEvery {
		r.check()
	}
	n, err := r.f.Write(p)
	r.written += int64(n)
	return n, err
}

// check reopens the path if another process rotated it, and rotates it if
// it's full. Failures leave the current file in use: losing rotation is
// better than losing log lines.
func (r *rotatingFile) check() {
	r.written = 0
	onDisk, err := os.Stat(r.path)
	mine, merr := r.f.Stat()
	if err != nil || merr != nil || !os.SameFile(onDisk, mine) {
		_ = r.open()
		return
	}
	if onDisk.Size() >= r.max {
		if os.Rename(r.path, r.path+".1") == nil {
			_ = r.open()
		}
	}
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}
