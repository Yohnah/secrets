package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// MockLogger for testing
type MockLogger struct {
	debugMessages []string
	infoMessages  []string
	errorMessages []string
	printMessages []string
}

func (m *MockLogger) Debug(msg string)   { m.debugMessages = append(m.debugMessages, msg) }
func (m *MockLogger) Info(msg string)    { m.infoMessages = append(m.infoMessages, msg) }
func (m *MockLogger) Success(msg string) { m.infoMessages = append(m.infoMessages, msg) }
func (m *MockLogger) Error(msg string)   { m.errorMessages = append(m.errorMessages, msg) }
func (m *MockLogger) Warning(msg string) { m.infoMessages = append(m.infoMessages, msg) }
func (m *MockLogger) Print(msg string)   { m.printMessages = append(m.printMessages, msg) }

func TestSecretsConfigManager_ValidSecretsYml(t *testing.T) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "secrets_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create valid secrets.yml
	validContent := `metadata:
  profile: "test-valid"
  default_environment: "development"
---
development:
  - name: DEV_DATABASE_URL
    entry: "/databases/development/main"
    key: "connection_string"
    type: "envvar"
  - name: DEV_API_KEY
    entry: "api_keys"
    key: "token"
    type: "envvar"

production:
  - name: PROD_SECRET_KEY
    entry: "/production/app/secrets"
    key: "secret_key"
    type: "envvar"
  - name: SSH_DEPLOY_KEY
    entry: "/production/ssh/deploy"
    key: "private_key"
    type: "ssh_agent"
---
# Reserved section for future features`

	configPath := filepath.Join(tempDir, "secrets.yml")
	if err := os.WriteFile(configPath, []byte(validContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Test loading
	logger := &MockLogger{}
	manager := NewSecretsConfigManager(logger)
	config, err := manager.LoadSecretsConfig(configPath)

	// Assertions
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if config == nil {
		t.Fatal("Expected config to be loaded")
	}

	if config.Metadata.Profile != "test-valid" {
		t.Errorf("Expected profile 'test-valid', got '%s'", config.Metadata.Profile)
	}

	if config.Metadata.DefaultEnvironment != "development" {
		t.Errorf("Expected default environment 'development', got '%s'", config.Metadata.DefaultEnvironment)
	}

	if len(config.Environments) != 2 {
		t.Errorf("Expected 2 environments, got %d", len(config.Environments))
	}

	// Check development environment
	devItems := config.Environments["development"]
	if len(devItems) != 2 {
		t.Errorf("Expected 2 items in development, got %d", len(devItems))
	}

	// Check production environment
	prodItems := config.Environments["production"]
	if len(prodItems) != 2 {
		t.Errorf("Expected 2 items in production, got %d", len(prodItems))
	}
}

func TestSecretsConfigManager_EmptyProfile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "secrets_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	invalidContent := `metadata:
  profile: ""
  default_environment: "development"
---
development:
  - name: DEV_SECRET
    entry: "test_entry"
    key: "password"
    type: "envvar"
---
# Section 3`

	configPath := filepath.Join(tempDir, "secrets.yml")
	if err := os.WriteFile(configPath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	logger := &MockLogger{}
	manager := NewSecretsConfigManager(logger)
	_, err = manager.LoadSecretsConfig(configPath)

	if err == nil {
		t.Error("Expected error for empty profile, got nil")
	}

	if err != nil && !containsString(err.Error(), "profile cannot be empty") {
		t.Errorf("Expected 'profile cannot be empty' error, got: %v", err)
	}
}

func TestSecretsConfigManager_InvalidEnvironmentName(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "secrets_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	invalidContent := `metadata:
  profile: "test"
  default_environment: "development"
---
development:
  - name: TEST_SECRET
    entry: "test_entry"
    key: "password"
    type: "envvar"

"invalid env":
  - name: TEST_SECRET2
    entry: "test_entry2"
    key: "password"
    type: "envvar"
---
# Section 3`

	configPath := filepath.Join(tempDir, "secrets.yml")
	if err := os.WriteFile(configPath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	logger := &MockLogger{}
	manager := NewSecretsConfigManager(logger)
	_, err = manager.LoadSecretsConfig(configPath)

	if err == nil {
		t.Error("Expected error for environment name with spaces, got nil")
	}

	if err != nil && !containsString(err.Error(), "environment name cannot contain spaces") {
		t.Errorf("Expected 'environment name cannot contain spaces' error, got: %v", err)
	}
}

func TestSecretsConfigManager_InvalidDefaultEnvironment(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "secrets_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	invalidContent := `metadata:
  profile: "test"
  default_environment: "invalid env"
---
development:
  - name: TEST_SECRET
    entry: "test_entry"
    key: "password"
    type: "envvar"
---
# Section 3`

	configPath := filepath.Join(tempDir, "secrets.yml")
	if err := os.WriteFile(configPath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	logger := &MockLogger{}
	manager := NewSecretsConfigManager(logger)
	_, err = manager.LoadSecretsConfig(configPath)

	if err == nil {
		t.Error("Expected error for default environment with spaces, got nil")
	}

	if err != nil && !containsString(err.Error(), "default_environment cannot contain spaces") {
		t.Errorf("Expected 'default_environment cannot contain spaces' error, got: %v", err)
	}
}

func TestSecretsConfigManager_NonexistentDefaultEnvironment(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "secrets_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	invalidContent := `metadata:
  profile: "test"
  default_environment: "nonexistent"
---
development:
  - name: DEV_SECRET
    entry: "test_entry"
    key: "password"
    type: "envvar"
---
# Section 3`

	configPath := filepath.Join(tempDir, "secrets.yml")
	if err := os.WriteFile(configPath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	logger := &MockLogger{}
	manager := NewSecretsConfigManager(logger)
	_, err = manager.LoadSecretsConfig(configPath)

	if err == nil {
		t.Error("Expected error for nonexistent default environment, got nil")
	}

	if err != nil && !containsString(err.Error(), "is not defined in environments section") {
		t.Errorf("Expected 'is not defined in environments section' error, got: %v", err)
	}
}

func TestSecretsConfigManager_InvalidItemType(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "secrets_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	invalidContent := `metadata:
  profile: "test"
  default_environment: "development"
---
development:
  - name: DEV_SECRET
    entry: "test_entry"
    key: "password"
    type: "invalid_type"
---
# Section 3`

	configPath := filepath.Join(tempDir, "secrets.yml")
	if err := os.WriteFile(configPath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	logger := &MockLogger{}
	manager := NewSecretsConfigManager(logger)
	_, err = manager.LoadSecretsConfig(configPath)

	if err == nil {
		t.Error("Expected error for invalid type, got nil")
	}

	if err != nil && !containsString(err.Error(), "type must be one of: envvar, ssh_agent") {
		t.Errorf("Expected 'type must be one of' error, got: %v", err)
	}
}

func TestSecretsConfigManager_InvalidEntryPath(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "secrets_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	invalidContent := `metadata:
  profile: "test"
  default_environment: "development"
---
development:
  - name: DEV_SECRET
    entry: "/invalid//path/entry"
    key: "password"
    type: "envvar"
---
# Section 3`

	configPath := filepath.Join(tempDir, "secrets.yml")
	if err := os.WriteFile(configPath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	logger := &MockLogger{}
	manager := NewSecretsConfigManager(logger)
	_, err = manager.LoadSecretsConfig(configPath)

	if err == nil {
		t.Error("Expected error for invalid entry path, got nil")
	}

	if err != nil && !containsString(err.Error(), "cannot contain empty segments") {
		t.Errorf("Expected 'cannot contain empty segments' error, got: %v", err)
	}
}

func TestSecretsConfigManager_EmptyEnvironment(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "secrets_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	invalidContent := `metadata:
  profile: "test"
  default_environment: "development"
---
development:
  - name: DEV_SECRET
    entry: "test_entry"
    key: "password"
    type: "envvar"

production:
  # Empty environment - no items
---
# Section 3`

	configPath := filepath.Join(tempDir, "secrets.yml")
	if err := os.WriteFile(configPath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	logger := &MockLogger{}
	manager := NewSecretsConfigManager(logger)
	_, err = manager.LoadSecretsConfig(configPath)

	if err == nil {
		t.Error("Expected error for empty environment, got nil")
	}

	if err != nil && !containsString(err.Error(), "cannot be empty") {
		t.Errorf("Expected 'cannot be empty' error, got: %v", err)
	}
}

func TestSecretsConfigManager_OnlyOneSection(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "secrets_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	invalidContent := `metadata:
  profile: "test"
  default_environment: "development"

# No --- separators, so this is only one document`

	configPath := filepath.Join(tempDir, "secrets.yml")
	if err := os.WriteFile(configPath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	logger := &MockLogger{}
	manager := NewSecretsConfigManager(logger)
	_, err = manager.LoadSecretsConfig(configPath)

	if err == nil {
		t.Error("Expected error for missing sections, got nil")
	}

	if err != nil && !containsString(err.Error(), "EOF") {
		t.Errorf("Expected EOF error for missing section, got: %v", err)
	}
}

func TestSecretsConfigManager_FileNotFound(t *testing.T) {
	logger := &MockLogger{}
	manager := NewSecretsConfigManager(logger)
	_, err := manager.LoadSecretsConfig("/nonexistent/path/secrets.yml")

	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}

	if err != nil && !containsString(err.Error(), "not found") {
		t.Errorf("Expected 'not found' error, got: %v", err)
	}
}

func TestSecretsConfigManager_FindSecretsConfigFile(t *testing.T) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "secrets_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create secrets.yml in temp directory
	secretsPath := filepath.Join(tempDir, "secrets.yml")
	if err := os.WriteFile(secretsPath, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	logger := &MockLogger{}
	manager := NewSecretsConfigManager(logger)
	
	// Test finding existing file
	foundPath, err := manager.FindSecretsConfigFile(tempDir)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	expectedPath := filepath.Join(tempDir, "secrets.yml")
	if foundPath != expectedPath {
		t.Errorf("Expected path '%s', got '%s'", expectedPath, foundPath)
	}

	// Test missing file
	_, err = manager.FindSecretsConfigFile("/nonexistent/directory")
	if err == nil {
		t.Error("Expected error for nonexistent directory, got nil")
	}
}

func TestValidateEntryPath(t *testing.T) {
	logger := &MockLogger{}
	manager := &DefaultSecretsConfigManager{logger: logger}

	testCases := []struct {
		path        string
		shouldError bool
		description string
	}{
		{"/group1/group2/entry", false, "valid path"},
		{"/single_entry", false, "single entry"},
		{"relative/path", true, "missing leading slash"},
		{"/ends/with/slash/", true, "ends with slash"},
		{"/double//slash", true, "double slash"},
		{"/", true, "only slash"},
		{"", true, "empty path"},
		{"/group1/ /entry", true, "space in segment"},
		{"/group1//entry", true, "empty segment"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			err := manager.validateEntryPath(tc.path)
			if tc.shouldError && err == nil {
				t.Errorf("Expected error for path '%s', got nil", tc.path)
			}
			if !tc.shouldError && err != nil {
				t.Errorf("Expected no error for path '%s', got: %v", tc.path, err)
			}
		})
	}
}

func TestValidateEnvironmentName(t *testing.T) {
	logger := &MockLogger{}
	manager := &DefaultSecretsConfigManager{logger: logger}

	testCases := []struct {
		name        string
		shouldError bool
		description string
	}{
		{"development", false, "valid name"},
		{"prod_env", false, "with underscore"},
		{"staging-01", false, "with hyphen and numbers"},
		{"test123", false, "with numbers"},
		{"", true, "empty name"},
		{"invalid env", true, "with space"},
		{" development", true, "leading space"},
		{"development ", true, "trailing space"},
		{"123invalid", true, "starts with number"},
		{"-invalid", true, "starts with hyphen"},
		{"_invalid", true, "starts with underscore"},
		{"env@test", true, "special character"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			err := manager.validateEnvironmentName(tc.name)
			if tc.shouldError && err == nil {
				t.Errorf("Expected error for name '%s', got nil", tc.name)
			}
			if !tc.shouldError && err != nil {
				t.Errorf("Expected no error for name '%s', got: %v", tc.name, err)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}