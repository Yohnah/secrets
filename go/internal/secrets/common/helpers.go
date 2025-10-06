package common

import (
"os"
"path/filepath"
)

// FileExists checks if a file exists at the given path
func FileExists(path string) bool {
_, err := os.Stat(path)
return err == nil
}

// MakeAbsolutePath converts a relative path to an absolute path
// If the path is already absolute, returns it unchanged
func MakeAbsolutePath(path string) string {
if filepath.IsAbs(path) {
return path
}
cwd, _ := os.Getwd()
return filepath.Join(cwd, path)
}
