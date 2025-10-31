package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// CliReader interface defines the contract for reading CLI flags
type CliReader interface {
	GetStringFlag(name string) (string, error)
	GetBoolFlag(name string) (bool, error)
	SetCommand(cmd *cobra.Command)
	AskConfirmation(question string) (bool, error)
	AskPassword(prompt string) (string, error)
	AskPasswordConfirm(prompt string) (string, error)
}

// CobraCliReader implements CliReader using Cobra
type CobraCliReader struct {
	cmd *cobra.Command
}

// NewCobraCliReader creates a new CLI reader
func NewCobraCliReader() CliReader {
	return &CobraCliReader{}
}

// SetCommand sets the current Cobra command
func (r *CobraCliReader) SetCommand(cmd *cobra.Command) {
	r.cmd = cmd
}

// GetStringFlag retrieves a string flag value
func (r *CobraCliReader) GetStringFlag(name string) (string, error) {
	if r.cmd == nil {
		return "", nil
	}
	return r.cmd.Flags().GetString(name)
}

// GetBoolFlag retrieves a boolean flag value
func (r *CobraCliReader) GetBoolFlag(name string) (bool, error) {
	if r.cmd == nil {
		return false, nil
	}
	return r.cmd.Flags().GetBool(name)
}

// AskConfirmation asks a yes/no question and returns the answer
func (r *CobraCliReader) AskConfirmation(question string) (bool, error) {
	fmt.Fprintf(os.Stderr, "%s ", question)

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read input: %w", err)
	}

	response = strings.TrimSpace(strings.ToLower(response))

	// Default to "yes" if empty (matches Y/n pattern)
	if response == "" || response == "y" || response == "yes" {
		return true, nil
	}

	return false, nil
}

// AskPassword asks for a password with hidden input
func (r *CobraCliReader) AskPassword(prompt string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s", prompt)

	// Read password with hidden input
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // New line after hidden input

	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	return string(passwordBytes), nil
}

// AskPasswordConfirm asks for password confirmation (double entry)
func (r *CobraCliReader) AskPasswordConfirm(prompt string) (string, error) {
	password1, err := r.AskPassword(prompt)
	if err != nil {
		return "", err
	}

	password2, err := r.AskPassword("Repeat your new password: ")
	if err != nil {
		return "", err
	}

	if password1 != password2 {
		return "", fmt.Errorf("passwords do not match")
	}

	return password1, nil
}
