package cli_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/cli"
	"github.com/spf13/cobra"
)

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestShowCommand_Template_Default(t *testing.T) {
	// Setup
	cmd := cli.NewShowCommand()

	// Capture output using a buffer as both stdout and stderr
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)

	// Execute show template command
	cmd.SetArgs([]string{"template"})
	err := cmd.Execute()

	// Assertions
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	result := output.String()

	// Verify template content
	expectedContent := []string{
		"SECRETS.YML TEMPLATE",
		"YOUR_PROFILE_NAME",
		"YOUR_DEFAULT_ENV",
		"---",
		"your_environment_name:",
		"YOUR_VARIABLE_NAME",
		"envvar",
		"YOUR_ENTRY_NAME",
		"Password",
		"EXAMPLES",
		"development:",
		"production:",
		"staging:",
		"SECTION 3: RESERVED",
	}

	for _, expected := range expectedContent {
		if !strings.Contains(result, expected) {
			t.Errorf("Expected template to contain '%s', but it was not found", expected)
		}
	}
}

func TestShowCommand_Template_Minimal(t *testing.T) {
	// Setup
	cmd := cli.NewShowCommand()

	// Capture output
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)

	// Execute show template command with minimal flag
	cmd.SetArgs([]string{"template", "--minimal"})
	err := cmd.Execute()

	// Assertions
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	result := output.String()

	// Verify minimal template content
	expectedContent := []string{
		"YOUR_PROFILE_NAME",
		"YOUR_DEFAULT_ENV",
		"---",
		"your_environment_name:",
		"YOUR_VARIABLE_NAME",
		"envvar",
		"YOUR_ENTRY_NAME",
		"Password",
	}

	for _, expected := range expectedContent {
		if !strings.Contains(result, expected) {
			t.Errorf("Expected minimal template to contain '%s', but it was not found", expected)
		}
	}

	// Verify minimal template does NOT contain comments and examples
	unexpectedContent := []string{
		"This template shows",
		"Replace placeholders",
		"EXAMPLES (remove these comments",
		"Environment variable name",
		"Creates subgroups:",
		"File attachment in KeePass",
	}

	for _, unexpected := range unexpectedContent {
		if strings.Contains(result, unexpected) {
			t.Errorf("Expected minimal template to NOT contain '%s', but it was found", unexpected)
		}
	}
}

func TestShowCommand_Structure(t *testing.T) {
	// Test that show command exists and has correct structure
	cmd := cli.NewShowCommand()

	// Verify command exists
	if cmd == nil {
		t.Fatal("Expected show command to exist")
	}

	// Verify command name
	if cmd.Use != "show" {
		t.Errorf("Expected command use to be 'show', got '%s'", cmd.Use)
	}

	// Verify subcommands exist
	templateCmd := findSubcommand(cmd, "template")
	if templateCmd == nil {
		t.Fatal("Expected 'template' subcommand to exist")
	}

	// Verify template command has minimal flag
	minimalFlag := templateCmd.Flags().Lookup("minimal")
	if minimalFlag == nil {
		t.Error("Expected 'template' subcommand to have 'minimal' flag")
	}
}

func TestShowCommand_InvalidSubcommand(t *testing.T) {
	// Setup
	cmd := cli.NewShowCommand()

	// Capture output
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)

	// Execute with invalid subcommand
	cmd.SetArgs([]string{"invalid"})
	err := cmd.Execute()

	// Should return error for invalid subcommand
	if err == nil {
		t.Error("Expected error for invalid subcommand, got nil")
	}
}

// Helper function to find subcommand
func findSubcommand(cmd *cobra.Command, name string) *cobra.Command {
	for _, subCmd := range cmd.Commands() {
		if subCmd.Use == name {
			return subCmd
		}
	}
	return nil
}
