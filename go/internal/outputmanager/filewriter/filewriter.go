package filewriter

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Yohnah/secrets/internal/loggermanager"
)

// FileWriter interface defines the contract for file operations
type FileWriter interface {
	CreateDirectory(path string, mode os.FileMode) error
	WriteFile(path string, content []byte, mode os.FileMode) error
}

// FileSystemWriter implements FileWriter using os package
type FileSystemWriter struct {
	logger loggermanager.Logger
}

// NewFileSystemWriter creates a new file system writer
func NewFileSystemWriter(logger loggermanager.Logger) FileWriter {
	return &FileSystemWriter{
		logger: logger,
	}
}

// CreateDirectory creates a directory with specified permissions
func (w *FileSystemWriter) CreateDirectory(path string, mode os.FileMode) error {
	if info, err := os.Stat(path); err == nil {
		if info.IsDir() {
			w.logger.Debug(fmt.Sprintf("Directory already exists: %s", path))
			return nil
		}
		return fmt.Errorf("path exists but is not a directory: %s", path)
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}
	w.logger.Debug(fmt.Sprintf("Created directory: %s (mode: %o)", path, mode))
	return nil
}

// WriteFile writes content to a file with specified permissions
func (w *FileSystemWriter) WriteFile(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := w.CreateDirectory(dir, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}
	w.logger.Debug(fmt.Sprintf("Wrote file: %s (mode: %o, size: %d bytes)", path, mode, len(content)))
	return nil
}
