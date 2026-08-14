//go:build linux

package queue

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// openRoot resolves every root component from a trusted descriptor. O_NOFOLLOW
// makes both existing roots and their parents fail closed if they are symlinks.
func openRoot(path string, create bool) (*os.File, error) {
	clean := filepath.Clean(path)
	anchor := "."
	if filepath.IsAbs(clean) {
		anchor = "/"
		clean = strings.TrimPrefix(clean, "/")
	}
	fd, err := unix.Open(anchor, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), anchor)
	if clean == "." || clean == "" {
		return current, nil
	}
	for _, component := range strings.Split(clean, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		if component == ".." {
			current.Close()
			return nil, fmt.Errorf("queue root contains parent traversal")
		}
		next, e := openChildDir(current, component, create)
		current.Close()
		if e != nil {
			return nil, e
		}
		current = next
	}
	return current, nil
}

func openChildDir(parent *os.File, name string, create bool) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
		return nil, fmt.Errorf("invalid directory component %q", name)
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err == unix.ENOENT && create {
		if e := unix.Mkdirat(int(parent.Fd()), name, 0700); e != nil && e != unix.EEXIST {
			return nil, e
		}
		fd, err = unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func readFileAt(dir *os.File, name string) ([]byte, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("entry is not a regular file")
	}
	return io.ReadAll(file)
}

func unlinkFileAt(dir *os.File, name string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("entry is not a regular file")
	}
	return unix.Unlinkat(int(dir.Fd()), name, 0)
}

func atomicWriteAt(dir *os.File, name string, data []byte, perm os.FileMode) error {
	return atomicWriteReaderAt(dir, name, bytes.NewReader(data), perm)
}

// atomicWriteReaderAt writes from r into a temp file within the pinned
// directory and renames it into place, so a large body never has to be held in
// memory to be stored durably.
func atomicWriteReaderAt(dir *os.File, name string, r io.Reader, perm os.FileMode) error {
	var target unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &target, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if target.Mode&unix.S_IFMT != unix.S_IFREG {
			return fmt.Errorf("target is a symlink or not a regular file")
		}
	} else if err != unix.ENOENT {
		return err
	}

	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	tmp := ".tmp_" + hex.EncodeToString(random[:])
	fd, err := unix.Openat(int(dir.Fd()), tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(perm.Perm()))
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), tmp)
	ok := false
	defer func() {
		if !ok {
			_ = unix.Unlinkat(int(dir.Fd()), tmp, 0)
		}
	}()
	if _, err := io.Copy(file, r); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// Both names are resolved by the same pinned directory descriptor; a
	// concurrent pathname swap cannot redirect this rename outside it.
	if err := unix.Renameat(int(dir.Fd()), tmp, int(dir.Fd()), name); err != nil {
		return err
	}
	ok = true
	return nil
}

// modTimeAt stats a name relative to an open directory.
//
// os.DirEntry.Info() cannot be used for this: these directories are opened with
// openat and wrapped by os.NewFile, so the DirEntry resolves its lstat against
// the process working directory rather than the descriptor, fails, and the
// caller silently skips every entry.
func modTimeAt(dir *os.File, name string) (time.Time, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return time.Time{}, err
	}
	return time.Unix(st.Mtim.Sec, st.Mtim.Nsec), nil
}
