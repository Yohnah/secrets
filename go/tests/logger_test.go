package test

import (
	"testing"

	"github.com/Yohnah/secrets/internal/cli"
)

func TestLogger(t *testing.T) {
	// Test logger creation
	logger := cli.NewLogger(false)
	if logger == nil {
		t.Fatal("NewLogger() returned nil")
	}
	
	// Test logger implements Logger interface
	_, ok := logger.(cli.Logger)
	if !ok {
		t.Fatal("NewLogger() doesn't implement Logger interface")
	}
}

func TestLoggerVerbose(t *testing.T) {
	// Test verbose logger
	verboseLogger := cli.NewLogger(true)
	if verboseLogger == nil {
		t.Fatal("NewLogger(true) returned nil")
	}
	
	// Test non-verbose logger
	nonVerboseLogger := cli.NewLogger(false)
	if nonVerboseLogger == nil {
		t.Fatal("NewLogger(false) returned nil")
	}
}

func TestLoggerMethods(t *testing.T) {
	logger := cli.NewLogger(true)
	
	// Test that all methods exist and can be called
	// These should not panic
	logger.Info("test info")
	logger.Debug("test debug")
	logger.Success("test success")
	logger.Error("test error")
}