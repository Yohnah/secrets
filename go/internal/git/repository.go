package git

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// RepositoryManager defines the interface for git repository operations
// Follows Interface Segregation Principle (ISP) - focused on repository detection
type RepositoryManager interface {
	// IsGitRepository checks if the current directory is within a git repository
	IsGitRepository() bool

	// FindGitRoot finds the root directory of the git repository
	// Returns empty string if not in a git repository
	FindGitRoot() (string, error)

	// EnsureGitIgnore adds the specified path to .gitignore if not already present
	EnsureGitIgnore(gitRoot, pathToIgnore string) error
}

// repositoryManager implements RepositoryManager interface
// Follows Single Responsibility Principle (SRP) - only handles git repository operations
type repositoryManager struct{}

// NewRepositoryManager creates a new repository manager
// Follows Factory Pattern for object creation
func NewRepositoryManager() RepositoryManager {
	return &repositoryManager{}
}

// IsGitRepository checks if the current directory is within a git repository
// Follows Single Responsibility Principle (SRP) - single method, single purpose
func (r *repositoryManager) IsGitRepository() bool {
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	err := cmd.Run()
	return err == nil
}

// FindGitRoot finds the root directory of the git repository
// Returns empty string if not in a git repository
// Follows Single Responsibility Principle (SRP) and Dependency Inversion Principle (DIP)
func (r *repositoryManager) FindGitRoot() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("not in a git repository or git command failed: %w", err)
	}

	gitRoot := strings.TrimSpace(string(output))
	if gitRoot == "" {
		return "", fmt.Errorf("git root directory is empty")
	}

	return gitRoot, nil
}

// EnsureGitIgnore adds the specified path to .gitignore if not already present
// Follows Open/Closed Principle (OCP) - extensible for different ignore patterns
func (r *repositoryManager) EnsureGitIgnore(gitRoot, pathToIgnore string) error {
	if gitRoot == "" {
		return fmt.Errorf("git root cannot be empty")
	}

	if pathToIgnore == "" {
		return fmt.Errorf("path to ignore cannot be empty")
	}

	gitignorePath := filepath.Join(gitRoot, ".gitignore")

	// Read existing .gitignore or create empty content
	var content []byte
	var err error
	if _, err := os.Stat(gitignorePath); err == nil {
		content, err = os.ReadFile(gitignorePath)
		if err != nil {
			return fmt.Errorf("failed to read .gitignore: %w", err)
		}
	}

	contentStr := string(content)

	// Check if path is already in .gitignore
	lines := strings.Split(contentStr, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == pathToIgnore {
			// Already present, no need to add
			return nil
		}
	}

	// Add the path to .gitignore
	if len(contentStr) > 0 && !strings.HasSuffix(contentStr, "\n") {
		contentStr += "\n"
	}
	contentStr += pathToIgnore + "\n"

	// Write updated .gitignore
	err = os.WriteFile(gitignorePath, []byte(contentStr), 0o644)
	if err != nil {
		return fmt.Errorf("failed to write .gitignore: %w", err)
	}

	return nil
}
