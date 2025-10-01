package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/viper"
	"golang.org/x/term"
)

// PasswordProvider interface follows ISP - Interface Segregation Principle
type PasswordProvider interface {
	GetPassword(prompt string) (string, error)
}

// InteractivePasswordProvider follows SRP - Single Responsibility for password input
type InteractivePasswordProvider struct {
	logger Logger
}

// NewPasswordProvider factory function follows DIP - Dependency Inversion Principle
func NewPasswordProvider(logger Logger) PasswordProvider {
	return &InteractivePasswordProvider{
		logger: logger,
	}
}

// GetPassword prompts for password input securely (hidden input)
// Returns password from environment variable if available, otherwise prompts interactively
func (p *InteractivePasswordProvider) GetPassword(prompt string) (string, error) {
	// Check if password is provided via environment variable
	envPassword := viper.GetString("password")
	if envPassword != "" {
		p.logger.Debug("Using password from environment variable SECRETS_YOHNAH_PASSWORD")
		return envPassword, nil
	}
	
	// No environment password, prompt interactively
	p.logger.Debug("No environment password found, prompting interactively")
	return p.promptPasswordSecurely(prompt)
}

// promptPasswordSecurely prompts for password with hidden input
func (p *InteractivePasswordProvider) promptPasswordSecurely(prompt string) (string, error) {
	fmt.Print(prompt)
	
	// Check if we're in a terminal (for secure password input)
	if term.IsTerminal(int(syscall.Stdin)) {
		// Use secure password input (hidden)
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println() // Print newline after hidden input
		if err != nil {
			return "", fmt.Errorf("error reading password: %v", err)
		}
		return string(bytePassword), nil
	} else {
		// Fallback for non-terminal environments (testing, pipes, etc.)
		reader := bufio.NewReader(os.Stdin)
		password, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("error reading password: %v", err)
		}
		return strings.TrimSpace(password), nil
	}
}