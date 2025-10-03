// Package prompt provides user interaction capabilities following DDD principles
// This package handles secure user input including password prompts and confirmations
package prompt

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// ConfirmationProvider defines the interface for user confirmation prompts
// Following Interface Segregation Principle (ISP) - specific interface for confirmation
type ConfirmationProvider interface {
	Confirm(message string) (bool, error)
	ConfirmWithDefault(message string, defaultYes bool) (bool, error)
}

// PasswordProvider defines the interface for secure password input
// Following Interface Segregation Principle (ISP) - specific interface for passwords
type PasswordProvider interface {
	GetPassword(prompt string) (string, error)
}

// InteractivePrompter implements both confirmation and password prompts
// Following Single Responsibility Principle (SRP) - handles user interaction
type InteractivePrompter struct {
	forceMode bool
	reader    *bufio.Reader
}

// NewInteractivePrompter creates a new interactive prompter
// Following Dependency Inversion Principle (DIP) - factory function
func NewInteractivePrompter(forceMode bool) *InteractivePrompter {
	return &InteractivePrompter{
		forceMode: forceMode,
		reader:    bufio.NewReader(os.Stdin),
	}
}

// Confirm prompts the user for confirmation unless force mode is enabled
// Returns true if user confirms or force mode is active
// Following Open/Closed Principle (OCP) - extensible for different confirmation types
func (p *InteractivePrompter) Confirm(message string) (bool, error) {
	return p.ConfirmWithDefault(message, false)
}

// ConfirmWithDefault prompts the user for confirmation with specified default
// Returns true if user confirms or force mode is active
// Following Open/Closed Principle (OCP) - extensible for different confirmation types
func (p *InteractivePrompter) ConfirmWithDefault(message string, defaultYes bool) (bool, error) {
	// Skip confirmation in force mode
	if p.forceMode {
		return true, nil
	}

	// Format the prompt based on default
	var prompt string
	if defaultYes {
		prompt = fmt.Sprintf("%s (Y/n): ", message)
	} else {
		prompt = fmt.Sprintf("%s (y/N): ", message)
	}

	fmt.Print(prompt)

	response, err := p.reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("error reading confirmation: %w", err)
	}

	response = strings.TrimSpace(strings.ToLower(response))

	// Handle empty response based on default
	if response == "" {
		return defaultYes, nil
	}

	// Handle explicit responses
	if response == "y" || response == "yes" {
		return true, nil
	}
	if response == "n" || response == "no" {
		return false, nil
	}

	// Invalid response, use default
	return defaultYes, nil
}

// GetPassword prompts for a password with hidden input
// Following Single Responsibility Principle (SRP) - dedicated password handling
func (p *InteractivePrompter) GetPassword(prompt string) (string, error) {
	fmt.Print(prompt)

	// Use terminal package for hidden input
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", fmt.Errorf("error reading password: %w", err)
	}

	fmt.Println() // Add newline after password input
	return string(password), nil
}
