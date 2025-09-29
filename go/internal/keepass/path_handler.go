// Package keepass provides KeePass implementation following SOLID principles
package keepass

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/Yohnah/secrets/internal/secrets"
)

// PathHandler handles all path-related operations (SRP - Single Responsibility)
type PathHandler struct{}

// NewPathHandler creates a new PathHandler
func NewPathHandler() secrets.PathHandler {
	return &PathHandler{}
}

// ValidatePath validates a database path
func (p *PathHandler) ValidatePath(path string) error {
	if path == "" {
		return errors.New("database path cannot be empty")
	}
	return nil
}

// NormalizePath normalizes a path
func (p *PathHandler) NormalizePath(path string) string {
	return filepath.Clean(path)
}

// SplitPath splits a path into components
func (p *PathHandler) SplitPath(path string) []string {
	normalized := strings.Trim(path, "/")
	if normalized == "" {
		return []string{}
	}
	return strings.Split(normalized, "/")
}

// GetKeyFilePath returns the keyfile path for a database
func (p *PathHandler) GetKeyFilePath(dbPath string) string {
	return dbPath + ".key"
}