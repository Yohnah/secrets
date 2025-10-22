package testutils

import (
	"path/filepath"
	"strings"
)

// NormalizePath converts any path separator to forward slash for cross-platform comparison
func NormalizePath(path string) string {
	return filepath.ToSlash(path)
}

// ContainsPath checks if a normalized path contains a pattern using Unix-style separators
func ContainsPath(path, pattern string) bool {
	normalizedPath := NormalizePath(path)
	normalizedPattern := NormalizePath(pattern)
	return strings.Contains(normalizedPath, normalizedPattern)
}

// GetRelativePath builds a relative path from parts and normalizes it
func GetRelativePath(paths ...string) string {
	return NormalizePath(filepath.Join(paths...))
}
