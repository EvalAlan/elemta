//go:build !linux

package queue

import (
	"fmt"
	"os"
)

// Pathname emulation cannot provide the descriptor-relative no-follow
// guarantees required by this backend. Unsupported platforms therefore fail
// closed rather than silently reintroducing check-then-use races.
func unsupportedFilesystem() error {
	return fmt.Errorf("secure filesystem backend requires Linux descriptor-relative operations")
}
func openRoot(string, bool) (*os.File, error)                   { return nil, unsupportedFilesystem() }
func openChildDir(*os.File, string, bool) (*os.File, error)     { return nil, unsupportedFilesystem() }
func readFileAt(*os.File, string) ([]byte, error)               { return nil, unsupportedFilesystem() }
func unlinkFileAt(*os.File, string) error                       { return unsupportedFilesystem() }
func atomicWriteAt(*os.File, string, []byte, os.FileMode) error { return unsupportedFilesystem() }
