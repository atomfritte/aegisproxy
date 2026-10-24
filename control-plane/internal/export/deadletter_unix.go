//go:build unix

package export

import (
	"os"
	"syscall"
)

// openAppendNoFollow opens path for appending; a symbolic link in its place is refused (ELOOP).
func openAppendNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	return requireRegular(f)
}
