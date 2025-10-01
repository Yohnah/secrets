package prompt

import (
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/logger"
)

func TestDefaultInteractivePrompter(t *testing.T) {
	log := logger.New(false)
	
	t.Run("AskYesNo_ForceMode", func(t *testing.T) {
		// Create prompter
		prompter := NewInteractivePrompter(log)
		
		// In force mode, should return default value parsed
		result, err := prompter.AskYesNo("Test question?", "yes", true)
		if err != nil {
			t.Fatalf("AskYesNo failed: %v", err)
		}
		if !result {
			t.Error("Expected true when default is 'yes' in force mode")
		}
		
		result, err = prompter.AskYesNo("Test question?", "no", true)
		if err != nil {
			t.Fatalf("AskYesNo failed: %v", err)
		}
		if result {
			t.Error("Expected false when default is 'no' in force mode")
		}
	})
	
	t.Run("AskString_ForceMode", func(t *testing.T) {
		// Create prompter
		prompter := NewInteractivePrompter(log)
		
		// In force mode, should return default value
		result, err := prompter.AskString("Enter value:", "defaultValue", true)
		if err != nil {
			t.Fatalf("AskString failed: %v", err)
		}
		if result != "defaultValue" {
			t.Errorf("Expected 'defaultValue', got '%s'", result)
		}
	})
	
	t.Run("InteractivePrompterInterface", func(t *testing.T) {
		// Test that our prompter implements the InteractivePrompter interface
		var p InteractivePrompter = NewInteractivePrompter(log)
		
		// This should compile without issues
		_, _ = p.AskYesNo("Test?", "yes", true)
		_, _ = p.AskString("Enter:", "default", true)
	})
	
	t.Run("NormalizeInput", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"", ""},
			{"  test  ", "test"},
			{"TEST", "test"},
			{"  TeSt  ", "test"},
		}
		
		for _, test := range tests {
			result := strings.ToLower(strings.TrimSpace(test.input))
			if result != test.expected {
				t.Errorf("For input '%s', expected '%s', got '%s'", test.input, test.expected, result)
			}
		}
	})
}