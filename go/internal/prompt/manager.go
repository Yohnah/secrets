package prompt

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// Manager defines the interface for user interaction
type Manager interface {
	Confirm(message string) (bool, error)
	ConfirmWithDefault(message string, defaultYes bool) (bool, error)
	PromptPassword(message string) (string, error)
	PromptPasswordConfirm(message string) (string, error)
}

type manager struct {
	reader *bufio.Reader
}

// NewManager creates a new PromptManager instance
func NewManager() Manager {
	return &manager{
		reader: bufio.NewReader(os.Stdin),
	}
}

// Confirm asks user for Y/n confirmation (default: No)
func (m *manager) Confirm(message string) (bool, error) {
	return m.ConfirmWithDefault(message, false)
}

// ConfirmWithDefault asks user for confirmation with custom default
func (m *manager) ConfirmWithDefault(message string, defaultYes bool) (bool, error) {
	var prompt string
	if defaultYes {
		prompt = fmt.Sprintf("%s (Y/n): ", message)
	} else {
		prompt = fmt.Sprintf("%s (y/N): ", message)
	}

	fmt.Fprint(os.Stderr, prompt)

	response, err := m.reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read input: %w", err)
	}

	response = strings.TrimSpace(strings.ToLower(response))

	// Empty response uses default
	if response == "" {
		return defaultYes, nil
	}

	return response == "y" || response == "yes", nil
}

// PromptPassword asks user for password without echoing input
func (m *manager) PromptPassword(message string) (string, error) {
	fmt.Fprint(os.Stderr, message)

	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // New line after password input

	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	return string(password), nil
}

// PromptPasswordConfirm asks user for password twice to confirm
// Returns error if passwords don't match
func (m *manager) PromptPasswordConfirm(message string) (string, error) {
	// First prompt
	password1, err := m.PromptPassword(message + " (first time): ")
	if err != nil {
		return "", err
	}

	// Second prompt
	password2, err := m.PromptPassword(message + " (confirm): ")
	if err != nil {
		return "", err
	}

	// Verify passwords match
	if password1 != password2 {
		return "", fmt.Errorf("passwords do not match")
	}

	return password1, nil
}
