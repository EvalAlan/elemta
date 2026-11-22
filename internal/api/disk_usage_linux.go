//go:build linux

package api

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// readDiskUsage measures the filesystem holding path as df does: space kept
// back for root doesn't count as free, since the mail services can't use it.
func readDiskUsage(path string) (diskUsage, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return diskUsage{}, fmt.Errorf("reading the filesystem of %s: %w", path, err)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return diskUsage{}, fmt.Errorf("reading %s: %w", path, err)
	}
	out := diskUsage{Path: path, Device: fmt.Sprint(st.Dev), FreeBytes: float64(fs.Bavail) * float64(fs.Bsize)}
	used := float64(fs.Blocks) - float64(fs.Bfree)
	if usable := used + float64(fs.Bavail); usable > 0 {
		out.SpacePercent = used / usable * 100
	}
	// Filesystems that make inodes as needed report none.
	if fs.Files > 0 {
		out.InodePercent = (float64(fs.Files) - float64(fs.Ffree)) / float64(fs.Files) * 100
	}
	return out, nil
}
