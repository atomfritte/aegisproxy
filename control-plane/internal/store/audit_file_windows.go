package store

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// openAuditFile opens an audit log file without following a symbolic link or junction at the final
// path component. Read handles share delete access, so the sink can rename (rotate) and remove
// (compress) generations while a slow export still reads them, as on Unix.
func openAuditFile(path string, write bool) (*os.File, error) {
	if write {
		if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
			return nil, &fs.PathError{Op: "open", Path: path, Err: errNotRegularFile}
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, err
		}
		return requireRegularFile(f)
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil,
		syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err} // errors.Is(err, fs.ErrNotExist) works on the Errno
	}
	return requireRegularFile(os.NewFile(uintptr(h), path))
}
