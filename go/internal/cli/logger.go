package cli

import "fmt"

// Logger interface follows ISP - Interface Segregation Principle
type Logger interface {
	Info(message string)
	Debug(message string)
	Success(message string)
	Error(message string)
}

// CLILogger follows SRP - Single Responsibility for logging
type CLILogger struct {
	verbose bool
}

// NewLogger factory function follows DIP - Dependency Inversion Principle
func NewLogger(verbose bool) Logger {
	return &CLILogger{
		verbose: verbose,
	}
}

// Info always shows - for important user information
func (l *CLILogger) Info(message string) {
	fmt.Printf("INFO: %s\n", message)
}

// Debug only shows with verbose flag - for development/troubleshooting
func (l *CLILogger) Debug(message string) {
	if l.verbose {
		fmt.Printf("DEBUG: %s\n", message)
	}
}

// Success always shows - for user feedback
func (l *CLILogger) Success(message string) {
	fmt.Printf("SUCCESS: %s\n", message)
}

// Error always shows - critical for user
func (l *CLILogger) Error(message string) {
	fmt.Printf("ERROR: %s\n", message)
}