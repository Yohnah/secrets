package cli

import (
	"fmt"
	"os/exec"
	"strings"
)

// GitRootFinder interface follows ISP - Interface Segregation Principle
type GitRootFinder interface {
	FindGitRoot() (string, error)
}

// DefaultGitRootFinder follows SRP - Single Responsibility for finding git root
type DefaultGitRootFinder struct {
	logger Logger
}

// NewGitRootFinder factory function follows DIP - Dependency Inversion Principle
func NewGitRootFinder(logger Logger) GitRootFinder {
	return &DefaultGitRootFinder{
		logger: logger,
	}
}

// FindGitRoot finds the root directory of the current git repository
func (g *DefaultGitRootFinder) FindGitRoot() (string, error) {
	g.logger.Debug("Looking for git repository root")
	
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("not in a git repository or git not available: %v", err)
	}
	
	gitRoot := strings.TrimSpace(string(output))
	g.logger.Debug("Found git root: " + gitRoot)
	
	return gitRoot, nil
}