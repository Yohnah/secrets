package logger

import (
	"fmt"
	"os"
)

// Manager defines the interface for logging
type Manager interface {
	Info(message string)
	Debug(message string)
	Error(message string)
	Success(message string)
}

type manager struct {
	verbose bool
}

// NewManager creates a new LoggerManager instance
func NewManager(verbose bool) Manager {
	return &manager{
		verbose: verbose,
	}
}

// Info prints an informational message (always shown)
func (m *manager) Info(message string) {
	fmt.Fprintln(os.Stderr, message)
}

// Debug prints a debug message (only if verbose=true)
func (m *manager) Debug(message string) {
	if m.verbose {
		fmt.Fprintf(os.Stderr, "[DEBUG] %s\n", message)
	}
}

// Error prints an error message (always shown)
func (m *manager) Error(message string) {
	fmt.Fprintf(os.Stderr, "ERROR: %s\n", message)
}

// Success prints a success message (always shown)
func (m *manager) Success(message string) {
	fmt.Fprintln(os.Stderr, message)
}
