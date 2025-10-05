package validator_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/validator"
)

// TestValidateConfigFile_ValidConfig tests validation of a valid config file
func TestValidateConfigFile_ValidConfig(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")

	validConfig := `database: /tmp/test.kdbx
keyfile: /tmp/test.keyfile
`
	if err := os.WriteFile(configPath, []byte(validConfig), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Validate
	validatorMgr := validator.NewManager()
	err := validatorMgr.ValidateConfigFile(configPath)
	if err != nil {
		t.Errorf("Expected valid config to pass validation, got error: %v", err)
	}
}

// TestValidateConfigFile_ValidConfigWithOptionalField tests validation with optional field
func TestValidateConfigFile_ValidConfigWithOptionalField(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")

	validConfig := `database: /tmp/test.kdbx
keyfile: /tmp/test.keyfile
no_create_database: true
`
	if err := os.WriteFile(configPath, []byte(validConfig), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	validatorMgr := validator.NewManager()
	err := validatorMgr.ValidateConfigFile(configPath)
	if err != nil {
		t.Errorf("Expected valid config with optional field to pass validation, got error: %v", err)
	}
}

// TestValidateConfigFile_UnknownField tests that unknown fields are rejected
func TestValidateConfigFile_UnknownField(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")

	invalidConfig := `database: /tmp/test.kdbx
keyfile: /tmp/test.keyfile
unknown_field: "this should fail"
`
	if err := os.WriteFile(configPath, []byte(invalidConfig), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	validatorMgr := validator.NewManager()
	err := validatorMgr.ValidateConfigFile(configPath)
	if err == nil {
		t.Error("Expected unknown field to fail validation, but it passed")
	}
	if err != nil && !contains(err.Error(), "unknown field") {
		t.Errorf("Expected error to mention 'unknown field', got: %v", err)
	}
}

// TestValidateConfigFile_MissingRequiredField tests that missing required fields are rejected
func TestValidateConfigFile_MissingRequiredField(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")

	// Missing 'keyfile' field
	invalidConfig := `database: /tmp/test.kdbx
`
	if err := os.WriteFile(configPath, []byte(invalidConfig), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	validatorMgr := validator.NewManager()
	err := validatorMgr.ValidateConfigFile(configPath)
	if err == nil {
		t.Error("Expected missing required field to fail validation, but it passed")
	}
	if err != nil && !contains(err.Error(), "keyfile") && !contains(err.Error(), "required") {
		t.Errorf("Expected error to mention missing 'keyfile' field, got: %v", err)
	}
}

// TestValidateConfigFile_InvalidType tests that wrong types are rejected
func TestValidateConfigFile_InvalidType(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")

	// no_create_database should be bool, not string
	invalidConfig := `database: /tmp/test.kdbx
keyfile: /tmp/test.keyfile
no_create_database: "not a boolean"
`
	if err := os.WriteFile(configPath, []byte(invalidConfig), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	validatorMgr := validator.NewManager()
	err := validatorMgr.ValidateConfigFile(configPath)
	if err == nil {
		t.Error("Expected invalid type to fail validation, but it passed")
	}
	if err != nil && !contains(err.Error(), "boolean") && !contains(err.Error(), "bool") {
		t.Errorf("Expected error to mention type mismatch, got: %v", err)
	}
}

// TestValidateConfigFile_InvalidYAML tests that malformed YAML is rejected
func TestValidateConfigFile_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")

	invalidConfig := `database: /tmp/test.kdbx
keyfile: [invalid yaml: structure
`
	if err := os.WriteFile(configPath, []byte(invalidConfig), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	validatorMgr := validator.NewManager()
	err := validatorMgr.ValidateConfigFile(configPath)
	if err == nil {
		t.Error("Expected invalid YAML to fail validation, but it passed")
	}
}

// TestValidateConfigFile_FileNotFound tests that non-existent files return error
func TestValidateConfigFile_FileNotFound(t *testing.T) {
	validatorMgr := validator.NewManager()
	err := validatorMgr.ValidateConfigFile("/path/that/does/not/exist.yml")
	if err == nil {
		t.Error("Expected non-existent file to fail validation, but it passed")
	}
}

// TestValidateTemplate_ValidTemplate tests validation of a valid template
func TestValidateTemplate_ValidTemplate(t *testing.T) {
	validTemplate := `# Configuration file
database: {{.Database}}
keyfile: {{.Keyfile}}
{{.NoCreateDatabaseLine}}
`
	validatorMgr := validator.NewManager()
	err := validatorMgr.ValidateTemplate(validTemplate)
	if err != nil {
		t.Errorf("Expected valid template to pass validation, got error: %v", err)
	}
}

// TestValidateTemplate_MissingVariable tests that missing variables are detected
func TestValidateTemplate_MissingVariable(t *testing.T) {
	// Missing {{.NoCreateDatabaseLine}}
	invalidTemplate := `# Configuration file
database: {{.Database}}
keyfile: {{.Keyfile}}
`
	validatorMgr := validator.NewManager()
	err := validatorMgr.ValidateTemplate(invalidTemplate)
	if err == nil {
		t.Error("Expected template with missing variable to fail validation, but it passed")
	}
	if err != nil && !contains(err.Error(), "NoCreateDatabaseLine") {
		t.Errorf("Expected error to mention missing variable, got: %v", err)
	}
}

// TestValidateTemplate_EmptyTemplate tests that empty templates are rejected
func TestValidateTemplate_EmptyTemplate(t *testing.T) {
	validatorMgr := validator.NewManager()
	err := validatorMgr.ValidateTemplate("")
	if err == nil {
		t.Error("Expected empty template to fail validation, but it passed")
	}
}

// TestValidateTemplate_UnbalancedBraces tests that unbalanced braces are detected
func TestValidateTemplate_UnbalancedBraces(t *testing.T) {
	invalidTemplate := `database: {{.Database}
keyfile: {{.Keyfile}}
`
	validatorMgr := validator.NewManager()
	err := validatorMgr.ValidateTemplate(invalidTemplate)
	if err == nil {
		t.Error("Expected template with unbalanced braces to fail validation, but it passed")
	}
	// The validator detects syntax errors which may report as missing variables or template errors
	// Just check that an error was returned
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
