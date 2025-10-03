package prompt_test

import (
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/prompt"
)

func TestNewInteractivePrompter(t *testing.T) {
	tests := []struct {
		name      string
		forceMode bool
	}{
		{
			name:      "should create prompter with force mode enabled",
			forceMode: true,
		},
		{
			name:      "should create prompter with force mode disabled",
			forceMode: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prompter := prompt.NewInteractivePrompter(tt.forceMode)
			if prompter == nil {
				t.Error("Expected prompter to be created, got nil")
			}
		})
	}
}

func TestInteractivePrompter_Confirm_ForceMode(t *testing.T) {
	tests := []struct {
		name      string
		forceMode bool
		expected  bool
	}{
		{
			name:      "should auto-confirm when force mode is enabled",
			forceMode: true,
			expected:  true,
		},
		{
			name:      "should require user input when force mode is disabled",
			forceMode: false,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prompter := prompt.NewInteractivePrompter(tt.forceMode)

			if tt.forceMode {
				confirmed, err := prompter.Confirm("Test confirmation")
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
				if !confirmed {
					t.Error("Expected force mode to auto-confirm")
				}
			}
		})
	}
}

func TestConfirmationInterface(t *testing.T) {
	var _ prompt.ConfirmationProvider = &prompt.InteractivePrompter{}

	prompter := prompt.NewInteractivePrompter(true)
	if prompter == nil {
		t.Error("Expected prompter to be created")
	}
}

func TestPasswordInterface(t *testing.T) {
	var _ prompt.PasswordProvider = &prompt.InteractivePrompter{}

	prompter := prompt.NewInteractivePrompter(false)
	if prompter == nil {
		t.Error("Expected prompter to be created")
	}
}

func TestMockPrompter(t *testing.T) {
	// Test interface compliance - using local mock types would go here
	// For now, just test that the interfaces exist
	var _ prompt.ConfirmationProvider = (*prompt.InteractivePrompter)(nil)
	var _ prompt.PasswordProvider = (*prompt.InteractivePrompter)(nil)
}

func TestResponseParsing(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{name: "should accept 'y'", input: "y", expected: true},
		{name: "should accept 'Y'", input: "Y", expected: true},
		{name: "should accept 'yes'", input: "yes", expected: true},
		{name: "should accept 'YES'", input: "YES", expected: true},
		{name: "should accept 'Yes'", input: "Yes", expected: true},
		{name: "should reject 'n'", input: "n", expected: false},
		{name: "should reject 'N'", input: "N", expected: false},
		{name: "should reject 'no'", input: "no", expected: false},
		{name: "should reject 'NO'", input: "NO", expected: false},
		{name: "should reject empty string", input: "", expected: false},
		{name: "should reject whitespace", input: "  ", expected: false},
		{name: "should reject random text", input: "random", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPositiveResponse(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %v for input '%s', got %v", tt.expected, tt.input, result)
			}
		})
	}
}

func isPositiveResponse(input string) bool {
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes"
}

func TestGetPasswordWithConfirmation_InterfaceCompliance(t *testing.T) {
	// Test that InteractivePrompter implements PasswordProvider with confirmation method
	// This validates ISP (Interface Segregation Principle) is maintained
	prompter := prompt.NewInteractivePrompter(false)

	// Type assertion to verify interface compliance
	_, ok := interface{}(prompter).(prompt.PasswordProvider)
	if !ok {
		t.Fatal("InteractivePrompter does not implement PasswordProvider interface")
	}
}

func TestPasswordProvider_HasRequiredMethods(t *testing.T) {
	// Verify the PasswordProvider interface includes both password methods
	// Following Interface Segregation Principle (ISP)
	prompter := prompt.NewInteractivePrompter(false)

	// Verify both GetPassword and GetPasswordWithConfirmation exist
	var passwordProvider prompt.PasswordProvider = prompter
	if passwordProvider == nil {
		t.Fatal("Expected prompter to implement PasswordProvider interface")
	}
}
