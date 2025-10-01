package cli

import (
	"testing"

	"github.com/Yohnah/secrets/internal/logger"
)

func TestDefaultLogger(t *testing.T) {
	t.Run("VerboseMode", func(t *testing.T) {
		log := logger.New(true)
		
		// These should not panic in verbose mode
		log.Debug("Debug message")
		log.Info("Info message")
		log.Success("Success message")
		log.Error("Error message")
		log.Warning("Warning message")
		log.Print("Print message")
	})
	
	t.Run("NonVerboseMode", func(t *testing.T) {
		log := logger.New(false)
		
		// These should not panic in non-verbose mode
		log.Debug("Debug message") // Should not print
		log.Info("Info message")   // Should not print
		log.Success("Success message")
		log.Error("Error message")
		log.Warning("Warning message")
		log.Print("Print message")
	})
	
	t.Run("LoggerInterface", func(t *testing.T) {
		// Test that our logger implements the Logger interface
		var log logger.Logger = logger.New(false)
		
		// This should compile without issues
		log.Debug("test")
		log.Info("test")
		log.Success("test")
		log.Error("test")
		log.Warning("test")
		log.Print("test")
	})
}