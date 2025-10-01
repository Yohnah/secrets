package git

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Yohnah/secrets/internal/logger"
)

// RootFinder interface follows ISP - Interface Segregation Principle
// Separates git operations from other concerns
type RootFinder interface {
	FindGitRoot() (string, error)
}

// DefaultRootFinder implements RootFinder interface
// Follows SRP - Single Responsibility Principle: only handles git root finding
type DefaultRootFinder struct {
	logger logger.Logger
}

// NewRootFinder creates a new git root finder
// Follows DIP - Dependency Inversion Principle: depends on Logger abstraction
func NewRootFinder(logger logger.Logger) RootFinder {
	return &DefaultRootFinder{
		logger: logger,
	}
}

// FindGitRoot searches for git repository root starting from current directory
func (g *DefaultRootFinder) FindGitRoot() (string, error) {
	g.logger.Debug("Searching for git repository root")
	
	// Get current working directory
	currentDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %v", err)
	}
	
	// Search upwards for .git directory
	for {
		gitDir := filepath.Join(currentDir, ".git")
		if _, err := os.Stat(gitDir); err == nil {
			g.logger.Debug("Git root found: " + currentDir)
			return currentDir, nil
		}
		
		// Move to parent directory
		parentDir := filepath.Dir(currentDir)
		
		// Check if we've reached the root of the filesystem
		if parentDir == currentDir {
			break
		}
		
		currentDir = parentDir
	}
	
	return "", fmt.Errorf("not in a git repository")
}