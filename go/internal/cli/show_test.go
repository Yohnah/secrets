package cli

import (
	"bytes"
	"fmt"
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
		t.Fatalf("\033[31mShow template command failed: %v\033[0m", err)
	}
	
	// Read captured output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()
	
	// Verify template content - essential structure only
	expectedContent := []string{
		"metadata:",
		"profile:",
		"default_environment:",
		"---",
		"environment_name:",
		"name:",
		"entry:",
		"key:",
		"type:",
		"envvar",
		"ssh_agent",
	}
	
	for _, expected := range expectedContent {
		if !strings.Contains(output, expected) {
			t.Errorf("\033[31mTemplate should contain '%s', but it was not found\033[0m", expected)
		}
	}
	
	// Verify it ends with newline
	if !strings.HasSuffix(output, "\n") {
		t.Error("\033[31mTemplate should end with newline\033[0m")
	}
}

func TestShowTemplateValidation(t *testing.T) {
	// Create a mock logger
	logger := &MockLogger{}
	
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "show_template_test")
	if err != nil {
		t.Fatalf("\033[31mFailed to create temp dir: %v\033[0m", err)
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
		t.Fatalf("\033[31mShow template command failed: %v\033[0m", err)
	}
	
	// Read captured output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	templateContent := buf.String()
	
	// Create a valid secrets config based on the template structure
	// Replace the placeholder with a real environment for testing
	validContent := strings.ReplaceAll(templateContent, "environment_name:", "development:")
	validContent = strings.ReplaceAll(validContent, "default_environment: \"environment_name\"", "default_environment: \"development\"")
	validContent = strings.ReplaceAll(validContent, "profile: \"profile_name\"", "profile: \"my-project\"")
	validContent = strings.ReplaceAll(validContent, "type: \"(envvar|ssh_agent)\"", "type: \"envvar\"")
	
	// Write template to file
	templateFile := tempDir + "/template.yml"
	err = os.WriteFile(templateFile, []byte(validContent), 0644)
	if err != nil {
		t.Fatalf("\033[31mFailed to write template file: %v\033[0m", err)
	}
	
	// Validate template using our secrets config manager
	manager := NewSecretsConfigManager(logger)
	config, err := manager.LoadSecretsConfig(templateFile)
	if err != nil {
		t.Fatalf("\033[31mGenerated template should be loadable, but got error: %v\033[0m", err)
	}
	
	// Validate the config
	err = manager.ValidateSecretsConfig(config)
	if err != nil {
		t.Fatalf("\033[31mGenerated template should be valid, but got error: %v\033[0m", err)
	}
	
	// Verify metadata
	if config.Metadata.Profile != "my-project" {
		t.Errorf("\033[31mExpected profile 'my-project', got '%s'\033[0m", config.Metadata.Profile)
	}
	
	if config.Metadata.DefaultEnvironment != "development" {
		t.Errorf("\033[31mExpected default environment 'development', got '%s'\033[0m", config.Metadata.DefaultEnvironment)
	}
	
	// Verify development environment exists and has items
	if _, exists := config.Environments["development"]; !exists {
		t.Error("\033[31mTemplate should include development environment after replacement\033[0m")
	}
	
	// Verify development environment has items
	items := config.Environments["development"]
	if len(items) == 0 {
		t.Error("\033[31mDevelopment environment should have items\033[0m")
	}
	
	// Verify first item structure
	item := items[0]
	if item.Name == "" {
		t.Error("\033[31mDevelopment environment items should have name\033[0m")
	}
	if item.Entry == "" {
		t.Error("\033[31mDevelopment environment items should have entry\033[0m")
	}
	if item.Key == "" {
		t.Error("\033[31mDevelopment environment items should have key\033[0m")
	}
	if item.Type == "" {
		t.Error("\033[31mDevelopment environment items should have type\033[0m")
	}
}

func TestShowTemplateMinimalFlag(t *testing.T) {
	app := NewApp()
	
	// Test normal template (without --minimal)
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	
	cliApp := app.(*CLIApp)
	cliApp.rootCmd.SetArgs([]string{"show", "template"})
	err := app.Execute()
	
	w.Close()
	os.Stdout = old
	
	if err != nil {
		t.Fatalf("\033[31mShow template command failed: %v\033[0m", err)
	}
	
	var normalBuf bytes.Buffer
	io.Copy(&normalBuf, r)
	normalOutput := normalBuf.String()
	
	// Test minimal template (with --minimal)
	r2, w2, _ := os.Pipe()
	os.Stdout = w2
	
	cliApp2 := app.(*CLIApp)
	cliApp2.rootCmd.SetArgs([]string{"show", "template", "--minimal"})
	err = app.Execute()
	
	w2.Close()
	os.Stdout = old
	
	if err != nil {
		t.Fatalf("\033[31mShow template --minimal command failed: %v\033[0m", err)
	}
	
	var minimalBuf bytes.Buffer
	io.Copy(&minimalBuf, r2)
	minimalOutput := minimalBuf.String()
	
	// Verify that normal output contains comments (any line starting with #)
	hasComments := false
	lines := strings.Split(normalOutput, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" && strings.HasPrefix(strings.TrimSpace(line), "#") {
			hasComments = true
			break
		}
	}
	if !hasComments {
		t.Error("\033[31mNormal template should contain some commented examples\033[0m")
	}
	
	// Verify that minimal output does NOT contain any comments
	minimalLines := strings.Split(minimalOutput, "\n")
	for _, line := range minimalLines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && strings.HasPrefix(trimmed, "#") {
			t.Error("\033[31mMinimal template should NOT contain any commented lines\033[0m")
			break
		}
	}
	
	// Verify that minimal output still contains essential parts
	essentialParts := []string{
		"metadata:",
		"profile: \"profile_name\"",
		"default_environment: \"environment_name\"",
		"---",
		"environment_name:",
		"- name: DATABASE_URL",
	}
	
	for _, part := range essentialParts {
		if !strings.Contains(minimalOutput, part) {
			t.Errorf("\033[31mMinimal template should contain '%s'\033[0m", part)
		}
	}
	
	// Verify that minimal output is shorter than normal output
	if len(minimalOutput) >= len(normalOutput) {
		t.Error("\033[31mMinimal template should be shorter than normal template\033[0m")
	}
}

func TestShowTemplateMinimalValidation(t *testing.T) {
	// Create a mock logger
	logger := &MockLogger{}
	
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "show_template_minimal_test")
	if err != nil {
		t.Fatalf("\033[31mFailed to create temp dir: %v\033[0m", err)
	}
	defer os.RemoveAll(tempDir)
	
	// Get minimal template content
	app := NewApp()
	cliApp := app.(*CLIApp)
	
	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	
	// Execute show template --minimal command
	cliApp.rootCmd.SetArgs([]string{"show", "template", "--minimal"})
	err = app.Execute()
	
	// Restore stdout
	w.Close()
	os.Stdout = old
	
	if err != nil {
		t.Fatalf("\033[31mShow template --minimal command failed: %v\033[0m", err)
	}
	
	// Read captured output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	templateContent := buf.String()
	
	// Create a valid secrets config based on the minimal template
	validContent := strings.ReplaceAll(templateContent, "environment_name:", "development:")
	validContent = strings.ReplaceAll(validContent, "default_environment: \"environment_name\"", "default_environment: \"development\"")
	validContent = strings.ReplaceAll(validContent, "profile: \"profile_name\"", "profile: \"test-project\"")
	validContent = strings.ReplaceAll(validContent, "type: \"(envvar|ssh_agent)\"", "type: \"envvar\"")
	
	// Write template to file
	templateFile := tempDir + "/minimal_template.yml"
	err = os.WriteFile(templateFile, []byte(validContent), 0644)
	if err != nil {
		t.Fatalf("\033[31mFailed to write minimal template file: %v\033[0m", err)
	}
	
	// Validate minimal template using our secrets config manager
	manager := NewSecretsConfigManager(logger)
	config, err := manager.LoadSecretsConfig(templateFile)
	if err != nil {
		t.Fatalf("\033[31mGenerated minimal template should be loadable, but got error: %v\033[0m", err)
	}
	
	// Validate the config
	err = manager.ValidateSecretsConfig(config)
	if err != nil {
		t.Fatalf("\033[31mGenerated minimal template should be valid, but got error: %v\033[0m", err)
	}
	
	// Verify metadata
	if config.Metadata.Profile != "test-project" {
		t.Errorf("\033[31mExpected profile 'test-project', got '%s'\033[0m", config.Metadata.Profile)
	}
	
	if config.Metadata.DefaultEnvironment != "development" {
		t.Errorf("\033[31mExpected default environment 'development', got '%s'\033[0m", config.Metadata.DefaultEnvironment)
	}
	
	// Verify development environment exists and has items
	if _, exists := config.Environments["development"]; !exists {
		t.Error("\033[31mMinimal template should include development environment after replacement\033[0m")
	}
	
	// Verify development environment has items
	items := config.Environments["development"]
	if len(items) == 0 {
		t.Error("\033[31mMinimal template development environment should have items\033[0m")
	}
	
	// Verify first item structure
	item := items[0]
	if item.Name != "DATABASE_URL" {
		t.Errorf("\033[31mExpected item name 'DATABASE_URL', got '%s'\033[0m", item.Name)
	}
	if item.Type != "envvar" {
		t.Errorf("\033[31mExpected item type 'envvar', got '%s'\033[0m", item.Type)
	}
}

func TestValidSecretsYmlFile(t *testing.T) {
	// Create a mock logger
	logger := &MockLogger{}
	
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "valid_secrets_test")
	if err != nil {
		t.Fatalf("\033[31mFailed to create temp dir: %v\033[0m", err)
	}
	defer os.RemoveAll(tempDir)
	
	// Create a valid secrets.yml file
	validSecretsContent := `metadata:
  profile: "my-awesome-project"
  default_environment: "local"
---
local:
  - name: DATABASE_URL
    entry: "/databases/local"
    key: "connection_string"
    type: "envvar"
  - name: API_SECRET
    entry: "/api/keys"
    key: "secret_token"
    type: "envvar"
  - name: SSH_KEY
    entry: "/ssh/deploy"
    key: "attachments/private_key"
    type: "ssh_agent"
    
production:
  - name: DATABASE_URL
    entry: "/databases/production"
    key: "connection_string"
    type: "envvar"
  - name: API_SECRET
    entry: "/api/keys"
    key: "prod_token"
    type: "envvar"
    
my-custom-env:
  - name: CUSTOM_VAR
    entry: "/custom/path"
    key: "value"
    type: "envvar"
`
	
	// Write valid file
	validFile := tempDir + "/valid_secrets.yml"
	err = os.WriteFile(validFile, []byte(validSecretsContent), 0644)
	if err != nil {
		t.Fatalf("\033[31mFailed to write valid secrets file: %v\033[0m", err)
	}
	
	// Validate using our secrets config manager
	manager := NewSecretsConfigManager(logger)
	config, err := manager.LoadSecretsConfig(validFile)
	if err != nil {
		t.Fatalf("\033[31mValid secrets file should be loadable, but got error: %v\033[0m", err)
	}
	
	// Validate the config
	err = manager.ValidateSecretsConfig(config)
	if err != nil {
		t.Fatalf("\033[31mValid secrets file should pass validation, but got error: %v\033[0m", err)
	}
	
	// Verify structure
	if config.Metadata.Profile != "my-awesome-project" {
		t.Errorf("\033[31mExpected profile 'my-awesome-project', got '%s'\033[0m", config.Metadata.Profile)
	}
	
	if config.Metadata.DefaultEnvironment != "local" {
		t.Errorf("\033[31mExpected default environment 'local', got '%s'\033[0m", config.Metadata.DefaultEnvironment)
	}
	
	// Verify environments exist
	expectedEnvs := []string{"local", "production", "my-custom-env"}
	for _, env := range expectedEnvs {
		if _, exists := config.Environments[env]; !exists {
			t.Errorf("\033[31mEnvironment '%s' should exist\033[0m", env)
		}
	}
	
	// Verify default environment exists
	if _, exists := config.Environments[config.Metadata.DefaultEnvironment]; !exists {
		t.Error("\033[31mDefault environment should exist in environments\033[0m")
	}
	
	// Verify local environment has correct items
	localItems := config.Environments["local"]
	if len(localItems) != 3 {
		t.Errorf("\033[31mLocal environment should have 3 items, got %d\033[0m", len(localItems))
	}
	
	// Verify different types are supported
	foundEnvvar := false
	foundSshAgent := false
	for _, item := range localItems {
		if item.Type == "envvar" {
			foundEnvvar = true
		}
		if item.Type == "ssh_agent" {
			foundSshAgent = true
		}
	}
	if !foundEnvvar {
		t.Error("\033[31mShould have envvar type items\033[0m")
	}
	if !foundSshAgent {
		t.Error("\033[31mShould have ssh_agent type items\033[0m")
	}
}

func TestInvalidSecretsYmlFile(t *testing.T) {
	// Create a mock logger
	logger := &MockLogger{}
	
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "invalid_secrets_test")
	if err != nil {
		t.Fatalf("\033[31mFailed to create temp dir: %v\033[0m", err)
	}
	defer os.RemoveAll(tempDir)
	
	// Test multiple invalid scenarios
	invalidCases := []struct {
		name    string
		content string
		error   string
	}{
		{
			name: "missing metadata",
			content: `---
local:
  - name: TEST
    entry: "/test"
    key: "value"
    type: "envvar"
`,
			error: "failed to parse environments section",
		},
		{
			name: "empty profile",
			content: `metadata:
  profile: ""
  default_environment: "local"
---
local:
  - name: TEST
    entry: "/test"
    key: "value"
    type: "envvar"
`,
			error: "profile cannot be empty",
		},
		{
			name: "invalid environment name with spaces",
			content: `metadata:
  profile: "test"
  default_environment: "my env"
---
"my env":
  - name: TEST
    entry: "/test"
    key: "value"
    type: "envvar"
`,
			error: "cannot contain spaces",
		},
		{
			name: "invalid item type",
			content: `metadata:
  profile: "test"
  default_environment: "local"
---
local:
  - name: TEST
    entry: "/test"
    key: "value"
    type: "invalid_type"
`,
			error: "type must be one of: envvar, ssh_agent",
		},
		{
			name: "invalid entry path",
			content: `metadata:
  profile: "test"
  default_environment: "local"
---
local:
  - name: TEST
    entry: "invalid/path"
    key: "value"
    type: "envvar"
`,
			error: "entry path must start with '/'",
		},
		{
			name: "nonexistent default environment",
			content: `metadata:
  profile: "test"
  default_environment: "nonexistent"
---
local:
  - name: TEST
    entry: "/test"
    key: "value"
    type: "envvar"
`,
			error: "is not defined in environments section",
		},
		{
			name: "empty environment",
			content: `metadata:
  profile: "test"
  default_environment: "local"
---
local: []
`,
			error: "environment 'local' cannot be empty",
		},
	}
	
	manager := NewSecretsConfigManager(logger)
	
	for i, testCase := range invalidCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Write invalid file
			invalidFile := fmt.Sprintf("%s/invalid_%d.yml", tempDir, i)
			err := os.WriteFile(invalidFile, []byte(testCase.content), 0644)
			if err != nil {
				t.Fatalf("\033[31mFailed to write invalid secrets file: %v\033[0m", err)
			}
			
			// Try to load and validate
			config, err := manager.LoadSecretsConfig(invalidFile)
			if err != nil {
				// Some errors occur during loading
				if !strings.Contains(err.Error(), testCase.error) {
					t.Errorf("\033[31mExpected error containing '%s', got: %v\033[0m", testCase.error, err)
				}
				return
			}
			
			// Try to validate
			err = manager.ValidateSecretsConfig(config)
			if err == nil {
				t.Errorf("\033[31mExpected validation to fail for case '%s', but it passed\033[0m", testCase.name)
				return
			}
			
			// Check error message contains expected text
			if !strings.Contains(err.Error(), testCase.error) {
				t.Errorf("\033[31mExpected error containing '%s', got: %v\033[0m", testCase.error, err)
			}
		})
	}
}