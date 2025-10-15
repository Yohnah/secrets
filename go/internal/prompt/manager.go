package prompt

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Yohnah/secrets/internal/secrets/common"
	"golang.org/x/term"
)

// Manager defines the interface for user interaction.
// PromptManager handles all user input and confirmation prompts.
// It provides secure password input with confirmation, boolean confirmations,
// and manages interactive vs non-interactive modes.
type Manager interface {
	Confirm(message string) (bool, error)
	ConfirmWithDefault(message string, defaultYes bool) (bool, error)
	PromptPassword(message string) (*common.SecureValue, error)
	PromptPasswordConfirm(message string) (*common.SecureValue, error)
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
func (m *manager) PromptPassword(message string) (*common.SecureValue, error) {
	fmt.Fprint(os.Stderr, message)

	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // New line after password input

	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	return common.NewSecureValue(string(password)), nil
}

// PromptPasswordConfirm asks user for password twice to confirm
// Returns error if passwords don't match
func (m *manager) PromptPasswordConfirm(message string) (*common.SecureValue, error) {
	// First prompt
	password1, err := m.PromptPassword(message + " (first time): ")
	if err != nil {
		return nil, err
	}

	// Second prompt
	password2, err := m.PromptPassword(message + " (confirm): ")
	if err != nil {
		password1.Clear() // Clean up on error
		return nil, err
	}

	// Verify passwords match
	if password1.String() != password2.String() {
		password1.Clear()
		password2.Clear()
		return nil, fmt.Errorf("passwords do not match")
	}

	password2.Clear() // Clean up the second password
	return password1, nil
}
