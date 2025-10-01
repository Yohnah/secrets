package logger

import (
	"fmt"
	"os"
)

// Logger interface follows ISP - Interface Segregation Principle
// Clients depend only on logging methods they need
type Logger interface {
	Debug(message string)
	Info(message string) 
	Success(message string)
	Error(message string)
	Warning(message string)
	Print(message string)
}

// DefaultLogger implements Logger interface
// Follows SRP - Single Responsibility Principle: only handles logging
type DefaultLogger struct {
	verbose bool
}

// New creates a new logger instance
// Follows DIP - Dependency Inversion Principle: factory function
func New(verbose bool) Logger {
	return &DefaultLogger{
		verbose: verbose,
	}
}

// Debug outputs debug messages only in verbose mode
func (l *DefaultLogger) Debug(message string) {
	if l.verbose {
		fmt.Printf("[DEBUG] %s\n", message)
	}
}

// Info outputs info messages only in verbose mode
func (l *DefaultLogger) Info(message string) {
	if l.verbose {
		fmt.Printf("[INFO] %s\n", message)
	}
}

// Success outputs success messages always (user feedback)
func (l *DefaultLogger) Success(message string) {
	fmt.Printf("✓ %s\n", message)
}

// Error outputs error messages always
func (l *DefaultLogger) Error(message string) {
	fmt.Fprintf(os.Stderr, "✗ Error: %s\n", message)
}

// Warning outputs warning messages always
func (l *DefaultLogger) Warning(message string) {
	fmt.Printf("⚠ Warning: %s\n", message)
}

// Print outputs regular messages always
func (l *DefaultLogger) Print(message string) {
	fmt.Println(message)
}