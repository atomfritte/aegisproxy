package store

import (
	"io/fs"
	"os"
	"syscall"
)

// openAuditFile opens an audit log file without following a symbolic link or junction at the final
// path component: FILE_FLAG_OPEN_REPARSE_POINT opens a reparse point itself instead of its target, and
// the handle is checked (GetFileInformationByHandle, GetFileType) before it is used, so there is no
// window between a check and the open. Read handles share delete access, so the sink can rename
// (rotate) and remove (compress) generations while a slow export still reads them, as on Unix; the
// write handle shares like os.OpenFile (the live log cannot be removed while the sink holds it).
func openAuditFile(path string, write bool) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	access := uint32(syscall.GENERIC_READ)
	share := uint32(syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE)
	disposition := uint32(syscall.OPEN_EXISTING)
	if write {
		access |= syscall.GENERIC_WRITE
		share = syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE
		disposition = syscall.OPEN_ALWAYS
	}
	h, err := syscall.CreateFile(p, access, share, nil, disposition, syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err} // errors.Is(err, fs.ErrNotExist) works on the Errno
	}
	if t, err := syscall.GetFileType(h); err != nil || t != syscall.FILE_TYPE_DISK {
		syscall.CloseHandle(h)
		return nil, &fs.PathError{Op: "open", Path: path, Err: errNotRegularFile}
	}
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &info); err != nil {
		syscall.CloseHandle(h)
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	if info.FileAttributes&(syscall.FILE_ATTRIBUTE_REPARSE_POINT|syscall.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		syscall.CloseHandle(h)
		return nil, &fs.PathError{Op: "open", Path: path, Err: errNotRegularFile}
	}
	return requireRegularFile(os.NewFile(uintptr(h), path))
}
