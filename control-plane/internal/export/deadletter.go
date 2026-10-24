package export

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// deadLetterMax bounds one dead-letter file (a variable for tests); deadLetterKeep older generations
// (dead-letter.jsonl.1 … .5) are kept.
var deadLetterMax int64 = 32 << 20

const deadLetterKeep = 5

var errNotRegular = errors.New("not a regular file (symbolic link, FIFO or device)")

func requireRegular(f *os.File) (*os.File, error) {
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, &fs.PathError{Op: "open", Path: f.Name(), Err: errNotRegular}
	}
	return f, nil
}

// rotateDeadLetter shifts the generations (.4 → .5, …, the live file → .1); the oldest is removed.
func rotateDeadLetter(path string) {
	_ = os.Remove(fmt.Sprintf("%s.%d", path, deadLetterKeep))
	for i := deadLetterKeep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1))
	}
	_ = os.Rename(path, path+".1")
}

// appendDeadLetter appends one line to the dead-letter file and makes it durable. The file is never
// opened through a symbolic link planted in its place.
func appendDeadLetter(path string, line []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() && fi.Size()+int64(len(line)) > deadLetterMax {
		rotateDeadLetter(path)
	}
	f, err := openAppendNoFollow(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
