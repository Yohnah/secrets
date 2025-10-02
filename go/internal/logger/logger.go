package logger

import (
	"fmt"
	"log"
	"os"
)

// Logger interface follows ISP - Interface Segregation Principle
type Logger interface {
	Debug(msg string)
	Info(msg string)
	Error(msg string)
	Success(msg string)
}

// DefaultLogger implements Logger interface
// Follows SRP - Single Responsibility Principle: only handles logging
type DefaultLogger struct {
	verbose bool
}

// NewLogger creates a new logger
// Follows DIP - Dependency Inversion Principle: returns interface
func NewLogger(verbose bool) Logger {
	return &DefaultLogger{
		verbose: verbose,
	}
}

// Debug logs debug messages (only when verbose is enabled)
func (l *DefaultLogger) Debug(msg string) {
	if l.verbose {
		log.Printf("[DEBUG] %s", msg)
	}
}

// Info logs info messages (only when verbose is enabled)
func (l *DefaultLogger) Info(msg string) {
	if l.verbose {
		log.Printf("[INFO] %s", msg)
	}
}

// Error logs error messages (always shown)
func (l *DefaultLogger) Error(msg string) {
	fmt.Fprintf(os.Stderr, "[ERROR] %s\n", msg)
}

// Success logs success messages (always shown)
func (l *DefaultLogger) Success(msg string) {
	fmt.Printf("✓ %s\n", msg)
}