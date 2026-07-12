//go:build linux

package queue

import "golang.org/x/sys/unix"

// acquireEnqueueLock is an advisory lock: the kernel releases it on process
// death, unlike a sentinel directory, so interrupted enqueue is retryable.
func acquireEnqueueLock(path string) (func(), error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// Never unlink this path: flock protects an inode, and replacing the inode
	// can split queued waiters into two independently locked generations.
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = unix.Close(fd) }, nil
}
