package cli

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestShowTemplateCommand(t *testing.T) {
	app := NewApp()
	
	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	
	// Execute show template command directly using CLIApp
	cliApp := app.(*CLIApp)
	cliApp.rootCmd.SetArgs([]string{"show", "template"})
	err := app.Execute()
	
	// Restore stdout
	w.Close()
	os.Stdout = old
	
	if err != nil {
		t.Fatalf("Show template command failed: %v", err)
	}
	
	// Read captured output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()
	
	// Verify template content
	expectedContent := []string{
		"metadata:",
		"profile:",
		"default_environment:",
		"---",
		"development:",
		"staging:",
		"production:",
		"name:",
		"entry:",
		"key:",
		"type:",
		"envvar",
		"ssh_agent",
		"attachments/",
	}
	
	for _, expected := range expectedContent {
		if !strings.Contains(output, expected) {
			t.Errorf("Template should contain '%s', but it was not found", expected)
		}
	}
	
	// Verify it ends with newline
	if !strings.HasSuffix(output, "\n") {
		t.Error("Template should end with newline")
	}
}

func TestShowTemplateValidation(t *testing.T) {
	// Create a mock logger
	logger := &MockLogger{}
	
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "show_template_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	// Get template content
	app := NewApp()
	cliApp := app.(*CLIApp)
	
	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	
	// Execute show template command
	cliApp.rootCmd.SetArgs([]string{"show", "template"})
	err = app.Execute()
	
	// Restore stdout
	w.Close()
	os.Stdout = old
	
	if err != nil {
		t.Fatalf("Show template command failed: %v", err)
	}
	
	// Read captured output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	templateContent := buf.String()
	
	// Write template to file
	templateFile := tempDir + "/template.yml"
	err = os.WriteFile(templateFile, []byte(templateContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write template file: %v", err)
	}
	
	// Validate template using our secrets config manager
	manager := NewSecretsConfigManager(logger)
	config, err := manager.LoadSecretsConfig(templateFile)
	if err != nil {
		t.Fatalf("Generated template should be loadable, but got error: %v", err)
	}
	
	// Validate the config
	err = manager.ValidateSecretsConfig(config)
	if err != nil {
		t.Fatalf("Generated template should be valid, but got error: %v", err)
	}
	
	// Verify metadata
	if config.Metadata.Profile != "my-project" {
		t.Errorf("Expected profile 'my-project', got '%s'", config.Metadata.Profile)
	}
	
	if config.Metadata.DefaultEnvironment != "development" {
		t.Errorf("Expected default environment 'development', got '%s'", config.Metadata.DefaultEnvironment)
	}
	
	// Verify environments exist
	environments := []string{"development", "staging", "production"}
	for _, env := range environments {
		if _, exists := config.Environments[env]; !exists {
			t.Errorf("Template should include environment '%s'", env)
		}
	}
	
	// Verify each environment has items
	for _, env := range environments {
		items := config.Environments[env]
		if len(items) == 0 {
			t.Errorf("Environment '%s' should have items", env)
		}
		
		// Verify first item structure
		item := items[0]
		if item.Name == "" {
			t.Errorf("Environment '%s' items should have name", env)
		}
		if item.Entry == "" {
			t.Errorf("Environment '%s' items should have entry", env)
		}
		if item.Key == "" {
			t.Errorf("Environment '%s' items should have key", env)
		}
		if item.Type == "" {
			t.Errorf("Environment '%s' items should have type", env)
		}
	}
}