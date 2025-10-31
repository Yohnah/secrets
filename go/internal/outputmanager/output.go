package outputmanager

import (
	"os"

	"github.com/Yohnah/secrets/internal/loggermanager"
	"github.com/Yohnah/secrets/internal/outputmanager/filewriter"
)

// Output interface defines the output management contract
type Output interface {
	CreateDir(path string, mode os.FileMode) error
	WriteFile(path string, content []byte, mode os.FileMode) error
}

// StandardOutput implements Output with file operations
type StandardOutput struct {
	logger     loggermanager.Logger
	fileWriter filewriter.FileWriter
}

// NewStandardOutput creates a new output manager
func NewStandardOutput(logger loggermanager.Logger) Output {
	return &StandardOutput{
		logger:     logger,
		fileWriter: filewriter.NewFileSystemWriter(logger),
	}
}

// CreateDir creates a directory with specified permissions
func (o *StandardOutput) CreateDir(path string, mode os.FileMode) error {
	return o.fileWriter.CreateDirectory(path, mode)
}

// WriteFile writes content to a file with specified permissions
func (o *StandardOutput) WriteFile(path string, content []byte, mode os.FileMode) error {
	return o.fileWriter.WriteFile(path, content, mode)
}
