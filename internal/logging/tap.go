package logging

// A second reader of the process's log, for shipping it (internal/logship).

import (
	"io"
	"os"
	"sync"
)

// tapEarlyLines is how much of start-up is kept for a tap installed after it.
const tapEarlyLines = 256

type logTap struct {
	mu    sync.RWMutex
	fn    func([]byte)
	early [][]byte
}

var tap logTap

// SetTap gives every line logged from now on to fn, after the lines logged
// since start. fn mustn't block or keep the slice, and mustn't log.
func SetTap(fn func(line []byte)) {
	tap.mu.Lock()
	defer tap.mu.Unlock()
	tap.fn = fn
	if fn == nil {
		return
	}
	for _, line := range tap.early {
		fn(line)
	}
	tap.early = nil
}

func (t *logTap) Write(p []byte) (int, error) {
	t.mu.RLock()
	fn := t.fn
	if fn != nil {
		fn(p)
	}
	t.mu.RUnlock()
	if fn == nil {
		t.mu.Lock()
		if t.fn == nil && len(t.early) < tapEarlyLines {
			t.early = append(t.early, append([]byte(nil), p...))
		}
		t.mu.Unlock()
	}
	return len(p), nil
}

type tappedStdout struct{}

func (tappedStdout) Write(p []byte) (int, error) {
	n, err := os.Stdout.Write(p)
	_, _ = tap.Write(p)
	return n, err
}

// Stdout is standard output as the tap sees it, for a component that makes
// its own logger and would otherwise be missing from shipped logs.
func Stdout() io.Writer { return tappedStdout{} }
