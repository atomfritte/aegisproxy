//go:build !windows

package store

import (
	"os"
	"syscall"
)

// openAuditFile opens an audit log file without following a symbolic link at the final path
// component and without blocking on a FIFO: O_NONBLOCK makes the open of a FIFO without a reader
// fail (ENXIO) instead of waiting forever while the store lock is held, and requireRegularFile
// rejects a FIFO that has a reader. On Unix an open handle keeps reading the original file after
// rotation renamed or compression removed it.
func openAuditFile(path string, write bool) (*os.File, error) {
	flag := os.O_RDONLY
	if write {
		flag = os.O_RDWR | os.O_CREATE
	}
	f, err := os.OpenFile(path, flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	return requireRegularFile(f)
}
