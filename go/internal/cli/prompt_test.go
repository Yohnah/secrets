package cli

import (
	"testing"

	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/prompt"
)

func TestDefaultInteractivePrompter(t *testing.T) {
	log := logger.New(false)
	prompter := prompt.NewInteractivePrompter(log)
	
	t.Run("AskYesNoForceMode", func(t *testing.T) {
		// Test force mode with default "yes"
		result, err := prompter.AskYesNo("Test question", "yes", true)
		if err != nil {
			t.Fatalf("AskYesNo failed: %v", err)
		}
		
		if !result {
			t.Error("Expected true when default is 'yes' in force mode")
		}
		
		// Test force mode with default "no"
		result, err = prompter.AskYesNo("Test question", "no", true)
		if err != nil {
			t.Fatalf("AskYesNo failed: %v", err)
		}
		
		if result {
			t.Error("Expected false when default is 'no' in force mode")
		}
	})
	
	t.Run("AskStringForceMode", func(t *testing.T) {
		defaultValue := "default_value"
		result, err := prompter.AskString("Test question", defaultValue, true)
		if err != nil {
			t.Fatalf("AskString failed: %v", err)
		}
		
		if result != defaultValue {
			t.Errorf("Expected '%s', got '%s'", defaultValue, result)
		}
	})
	
	t.Run("InteractivePrompterInterface", func(t *testing.T) {
		// Test that our prompter implements the InteractivePrompter interface
		var prompter prompt.InteractivePrompter = prompt.NewInteractivePrompter(log)
		
		// This should compile without issues
		_, _ = prompter.AskYesNo("test", "yes", true)
		_, _ = prompter.AskString("test", "default", true)
	})
}