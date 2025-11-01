package outputmanager

import (
"os"
"github.com/Yohnah/secrets/internal/loggermanager"
"github.com/Yohnah/secrets/internal/outputmanager/filewriter"
)

type Output interface {
CreateDir(path string, mode os.FileMode) error
WriteFile(path string, content []byte, mode os.FileMode) error
}

type StandardOutput struct {
logger     loggermanager.Logger
fileWriter filewriter.FileWriter
}

func NewStandardOutput(logger loggermanager.Logger) Output {
return &StandardOutput{
logger:     logger,
fileWriter: filewriter.NewFileSystemWriter(logger),
}
}

func (o *StandardOutput) CreateDir(path string, mode os.FileMode) error {
return o.fileWriter.CreateDirectory(path, mode)
}

func (o *StandardOutput) WriteFile(path string, content []byte, mode os.FileMode) error {
return o.fileWriter.WriteFile(path, content, mode)
}
