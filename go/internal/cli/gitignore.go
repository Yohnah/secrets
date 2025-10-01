package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GitIgnoreManager interface follows ISP - Interface Segregation Principle
type GitIgnoreManager interface {
	EnsureSecretsIgnored(gitRoot string) error
}

// DefaultGitIgnoreManager follows SRP - Single Responsibility for managing .gitignore
type DefaultGitIgnoreManager struct {
	logger Logger
}

// NewGitIgnoreManager factory function follows DIP - Dependency Inversion Principle
func NewGitIgnoreManager(logger Logger) GitIgnoreManager {
	return &DefaultGitIgnoreManager{
		logger: logger,
	}
}

// EnsureSecretsIgnored ensures .secrets_yohnah is in .gitignore
func (g *DefaultGitIgnoreManager) EnsureSecretsIgnored(gitRoot string) error {
	gitignorePath := filepath.Join(gitRoot, ".gitignore")
	
	g.logger.Debug("Checking .gitignore file: " + gitignorePath)
	
	// Check if .gitignore exists
	if _, err := os.Stat(gitignorePath); os.IsNotExist(err) {
		g.logger.Debug(".gitignore does not exist, creating it")
		return g.createGitIgnoreWithSecrets(gitignorePath)
	}
	
	// Check if .secrets_yohnah is already in .gitignore
	isIgnored, err := g.isSecretsIgnored(gitignorePath)
	if err != nil {
		return fmt.Errorf("failed to check .gitignore: %v", err)
	}
	
	if isIgnored {
		g.logger.Debug(".secrets_yohnah is already in .gitignore")
		return nil
	}
	
	g.logger.Debug(".secrets_yohnah not found in .gitignore, adding it")
	return g.addSecretsToGitIgnore(gitignorePath)
}

// isSecretsIgnored checks if .secrets_yohnah is already in .gitignore
func (g *DefaultGitIgnoreManager) isSecretsIgnored(gitignorePath string) (bool, error) {
	file, err := os.Open(gitignorePath)
	if err != nil {
		return false, err
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Check for exact match or patterns that would cover .secrets_yohnah
		if line == ".secrets_yohnah" ||
		   line == ".secrets_yohnah/" ||
		   line == "/.secrets_yohnah" ||
		   line == "/.secrets_yohnah/" ||
		   line == "**/.secrets_yohnah" ||
		   line == "**/.secrets_yohnah/" {
			return true, nil
		}
	}
	
	return false, scanner.Err()
}

// addSecretsToGitIgnore adds .secrets_yohnah to existing .gitignore
func (g *DefaultGitIgnoreManager) addSecretsToGitIgnore(gitignorePath string) error {
	// Read existing content
	content, err := os.ReadFile(gitignorePath)
	if err != nil {
		return err
	}
	
	// Prepare the addition
	secretsEntry := "\n# Secrets directory - never commit (added by secrets CLI)\n.secrets_yohnah\n"
	
	// Check if file ends with newline
	contentStr := string(content)
	if len(contentStr) > 0 && !strings.HasSuffix(contentStr, "\n") {
		secretsEntry = "\n" + secretsEntry
	}
	
	// Append to file
	file, err := os.OpenFile(gitignorePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	
	if _, err := file.WriteString(secretsEntry); err != nil {
		return err
	}
	
	g.logger.Success("Added .secrets_yohnah to .gitignore")
	return nil
}

// createGitIgnoreWithSecrets creates a new .gitignore with .secrets_yohnah entry
func (g *DefaultGitIgnoreManager) createGitIgnoreWithSecrets(gitignorePath string) error {
	content := `# Secrets directory - never commit
.secrets_yohnah
`
	
	if err := os.WriteFile(gitignorePath, []byte(content), 0644); err != nil {
		return err
	}
	
	g.logger.Success("Created .gitignore with .secrets_yohnah entry")
	return nil
}