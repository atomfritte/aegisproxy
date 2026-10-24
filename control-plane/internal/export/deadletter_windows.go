//go:build windows

package export

import (
	"io/fs"
	"os"
)

// openAppendNoFollow opens path for appending; a symbolic link or junction in its place is refused.
// Windows has no O_NOFOLLOW: the path is checked before opening and the opened handle must be the
// file that was checked.
func openAppendNoFollow(path string) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return nil, &fs.PathError{Op: "open", Path: path, Err: errNotRegular}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if f, err = requireRegular(f); err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() || !os.SameFile(fi, opened) {
		f.Close()
		return nil, &fs.PathError{Op: "open", Path: path, Err: errNotRegular}
	}
	return f, nil
}
