package loggermanager

import (
	"fmt"
	"os"
)

// Logger interface defines the logging contract
type Logger interface {
	Debug(msg string)
	Info(msg string)
	Warn(msg string)
	Error(msg string)
	Fatal(msg string)
	SetVerbose(verbose bool)
}

// StderrLogger implements Logger writing to stderr
type StderrLogger struct {
	verbose bool
}

// NewStderrLogger creates a new logger that writes to stderr
func NewStderrLogger() Logger {
	return &StderrLogger{verbose: false}
}

// SetVerbose enables or disables verbose mode
func (l *StderrLogger) SetVerbose(verbose bool) {
	l.verbose = verbose
}

// Debug logs debug messages (only in verbose mode)
func (l *StderrLogger) Debug(msg string) {
	if l.verbose {
		fmt.Fprintf(os.Stderr, "[DEBUG] %s\n", msg)
	}
}

// Info logs informational messages
func (l *StderrLogger) Info(msg string) {
	if l.verbose {
		fmt.Fprintf(os.Stderr, "[INFO] %s\n", msg)
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", msg)
	}
}

// Warn logs warning messages
func (l *StderrLogger) Warn(msg string) {
	if l.verbose {
		fmt.Fprintf(os.Stderr, "[WARN] %s\n", msg)
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", msg)
	}
}

// Error logs error messages
func (l *StderrLogger) Error(msg string) {
	if l.verbose {
		fmt.Fprintf(os.Stderr, "[ERROR] %s\n", msg)
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", msg)
	}
}

// Fatal logs fatal error and exits with code 1
func (l *StderrLogger) Fatal(msg string) {
	if l.verbose {
		fmt.Fprintf(os.Stderr, "[FATAL] %s\n", msg)
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", msg)
	}
	os.Exit(1)
}
