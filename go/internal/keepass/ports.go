package keepass

import (
	"io/fs"
	"os"
)

// FileSystemPort defines the operations required from the underlying file system.
type FileSystemPort interface {
	Open(name string) (*os.File, error)
	OpenFile(name string, flag int, perm fs.FileMode) (*os.File, error)
	WriteFile(name string, data []byte, perm fs.FileMode) error
	IsNotExist(err error) bool
}

// osFileSystemAdapter implements FileSystemPort using the standard library.
type osFileSystemAdapter struct{}

func (osFileSystemAdapter) Open(name string) (*os.File, error) {
	return os.Open(name)
}

func (osFileSystemAdapter) OpenFile(name string, flag int, perm fs.FileMode) (*os.File, error) {
	return os.OpenFile(name, flag, perm)
}

func (osFileSystemAdapter) WriteFile(name string, data []byte, perm fs.FileMode) error {
	return os.WriteFile(name, data, perm)
}

func (osFileSystemAdapter) IsNotExist(err error) bool {
	return os.IsNotExist(err)
}
