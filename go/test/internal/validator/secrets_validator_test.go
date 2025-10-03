package validator_test

import (
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/validator"
)

// Test ValidateFile with valid YAML structure
func TestSecretsValidator_ValidateFile_ValidStructure(t *testing.T) {
	v := validator.NewSecretsValidator()

	validYAML := `profile: "test_profile"
default_environment: "development"

---

development:
  - name: "DATABASE_URL"
    type: "envvar"
    entry: "DATABASE_URL"
    key: "Password"

  - name: "API_TOKEN"
    type: "envvar"
    entry: "/api/tokens/MAIN_TOKEN"
    key: "Password"

production:
  - name: "PROD_DB"
    type: "envvar"
    entry: "PRODUCTION_DB"
    key: "Password"

---

# Reserved section`

	config, err := v.ValidateFile([]byte(validYAML))
	if err != nil {
		t.Fatalf("Expected valid YAML to pass validation, got error: %v", err)
	}

	if config.Metadata.Profile != "test_profile" {
		t.Errorf("Expected profile 'test_profile', got '%s'", config.Metadata.Profile)
	}

	if config.Metadata.DefaultEnvironment != "development" {
		t.Errorf("Expected default_environment 'development', got '%s'", config.Metadata.DefaultEnvironment)
	}

	if len(config.Environments) != 2 {
		t.Errorf("Expected 2 environments, got %d", len(config.Environments))
	}
}

// Test ValidateFile with missing sections
func TestSecretsValidator_ValidateFile_MissingSections(t *testing.T) {
	v := validator.NewSecretsValidator()

	invalidYAML := `profile: "test_profile"
default_environment: "development"

---

development:
  - name: "DATABASE_URL"
    type: "envvar"
    entry: "DATABASE_URL"
    key: "Password"`

	_, err := v.ValidateFile([]byte(invalidYAML))
	if err == nil {
		t.Fatal("Expected error for missing third section, got nil")
	}

	expectedError := "secrets.yml must have exactly 3 sections separated by '---', found 2 sections"
	if err.Error() != expectedError {
		t.Errorf("Expected error: %s, got: %s", expectedError, err.Error())
	}
}

// Test ValidateFile with invalid YAML syntax
func TestSecretsValidator_ValidateFile_InvalidYAMLSyntax(t *testing.T) {
	v := validator.NewSecretsValidator()

	invalidYAML := `profile: "test_profile"
default_environment: "development"
invalid_yaml: [unclosed

---

development:
  - name: "DATABASE_URL"
    type: "envvar"

---`

	_, err := v.ValidateFile([]byte(invalidYAML))
	if err == nil {
		t.Fatal("Expected error for invalid YAML syntax, got nil")
	}

	if !strings.Contains(err.Error(), "failed to parse metadata section") {
		t.Errorf("Expected metadata parsing error, got: %s", err.Error())
	}
}

// Test metadata validation - missing profile
func TestSecretsValidator_ValidateStructure_MissingProfile(t *testing.T) {
	v := validator.NewSecretsValidator()

	config := &validator.SecretsConfig{
		Metadata: validator.MetadataSection{
			Profile:            "",
			DefaultEnvironment: "development",
		},
		Environments: validator.EnvironmentsSection{
			"development": []validator.SecretItem{
				{Name: "TEST", Type: "envvar", Entry: "TEST", Key: "Password"},
			},
		},
	}

	err := v.ValidateStructure(config)
	if err == nil {
		t.Fatal("Expected error for missing profile, got nil")
	}

	if !strings.Contains(err.Error(), "profile field is required and cannot be empty") {
		t.Errorf("Expected profile validation error, got: %s", err.Error())
	}
}

// Test metadata validation - profile with spaces
func TestSecretsValidator_ValidateStructure_ProfileWithSpaces(t *testing.T) {
	v := validator.NewSecretsValidator()

	config := &validator.SecretsConfig{
		Metadata: validator.MetadataSection{
			Profile:            "test profile",
			DefaultEnvironment: "development",
		},
		Environments: validator.EnvironmentsSection{
			"development": []validator.SecretItem{
				{Name: "TEST", Type: "envvar", Entry: "TEST", Key: "Password"},
			},
		},
	}

	err := v.ValidateStructure(config)
	if err == nil {
		t.Fatal("Expected error for profile with spaces, got nil")
	}

	if !strings.Contains(err.Error(), "profile field cannot contain spaces") {
		t.Errorf("Expected profile spaces validation error, got: %s", err.Error())
	}
}

// Test metadata validation - missing default_environment
func TestSecretsValidator_ValidateStructure_MissingDefaultEnvironment(t *testing.T) {
	v := validator.NewSecretsValidator()

	config := &validator.SecretsConfig{
		Metadata: validator.MetadataSection{
			Profile:            "test_profile",
			DefaultEnvironment: "",
		},
		Environments: validator.EnvironmentsSection{
			"development": []validator.SecretItem{
				{Name: "TEST", Type: "envvar", Entry: "TEST", Key: "Password"},
			},
		},
	}

	err := v.ValidateStructure(config)
	if err == nil {
		t.Fatal("Expected error for missing default_environment, got nil")
	}

	if !strings.Contains(err.Error(), "default_environment field is required and cannot be empty") {
		t.Errorf("Expected default_environment validation error, got: %s", err.Error())
	}
}

// Test environments validation - no environments defined
func TestSecretsValidator_ValidateStructure_NoEnvironments(t *testing.T) {
	v := validator.NewSecretsValidator()

	config := &validator.SecretsConfig{
		Metadata: validator.MetadataSection{
			Profile:            "test_profile",
			DefaultEnvironment: "development",
		},
		Environments: validator.EnvironmentsSection{},
	}

	err := v.ValidateStructure(config)
	if err == nil {
		t.Fatal("Expected error for no environments, got nil")
	}

	if !strings.Contains(err.Error(), "at least one environment must be defined") {
		t.Errorf("Expected no environments validation error, got: %s", err.Error())
	}
}

// Test environments validation - environment name with spaces
func TestSecretsValidator_ValidateStructure_EnvironmentWithSpaces(t *testing.T) {
	v := validator.NewSecretsValidator()

	config := &validator.SecretsConfig{
		Metadata: validator.MetadataSection{
			Profile:            "test_profile",
			DefaultEnvironment: "development", // Valid default_environment
		},
		Environments: validator.EnvironmentsSection{
			"dev env": []validator.SecretItem{ // Invalid environment name with spaces
				{Name: "TEST", Type: "envvar", Entry: "TEST", Key: "Password"},
			},
			"development": []validator.SecretItem{ // Valid environment for default_environment
				{Name: "TEST2", Type: "envvar", Entry: "TEST2", Key: "Password"},
			},
		},
	}

	err := v.ValidateStructure(config)
	if err == nil {
		t.Fatal("Expected error for environment name with spaces, got nil")
	}

	if !strings.Contains(err.Error(), "environment name 'dev env' cannot contain spaces") {
		t.Errorf("Expected environment spaces validation error, got: %s", err.Error())
	}
}

// Test environments validation - no items in environment
func TestSecretsValidator_ValidateStructure_EmptyEnvironment(t *testing.T) {
	v := validator.NewSecretsValidator()

	config := &validator.SecretsConfig{
		Metadata: validator.MetadataSection{
			Profile:            "test_profile",
			DefaultEnvironment: "development",
		},
		Environments: validator.EnvironmentsSection{
			"development": []validator.SecretItem{},
		},
	}

	err := v.ValidateStructure(config)
	if err == nil {
		t.Fatal("Expected error for empty environment, got nil")
	}

	if !strings.Contains(err.Error(), "environment 'development' must have at least one item") {
		t.Errorf("Expected empty environment validation error, got: %s", err.Error())
	}
}

// Test secret item validation - invalid type
func TestSecretsValidator_ValidateStructure_InvalidSecretType(t *testing.T) {
	v := validator.NewSecretsValidator()

	config := &validator.SecretsConfig{
		Metadata: validator.MetadataSection{
			Profile:            "test_profile",
			DefaultEnvironment: "development",
		},
		Environments: validator.EnvironmentsSection{
			"development": []validator.SecretItem{
				{Name: "TEST", Type: "invalid_type", Entry: "TEST", Key: "Password"},
			},
		},
	}

	err := v.ValidateStructure(config)
	if err == nil {
		t.Fatal("Expected error for invalid secret type, got nil")
	}

	if !strings.Contains(err.Error(), "invalid type 'invalid_type', must be one of: envvar, text, ssh_agent") {
		t.Errorf("Expected invalid type validation error, got: %s", err.Error())
	}
}

// Test secret item validation - missing required fields
func TestSecretsValidator_ValidateStructure_MissingSecretFields(t *testing.T) {
	v := validator.NewSecretsValidator()

	config := &validator.SecretsConfig{
		Metadata: validator.MetadataSection{
			Profile:            "test_profile",
			DefaultEnvironment: "development",
		},
		Environments: validator.EnvironmentsSection{
			"development": []validator.SecretItem{
				{Name: "", Type: "envvar", Entry: "TEST", Key: "Password"},
			},
		},
	}

	err := v.ValidateStructure(config)
	if err == nil {
		t.Fatal("Expected error for missing name field, got nil")
	}

	if !strings.Contains(err.Error(), "name field is required and cannot be empty") {
		t.Errorf("Expected missing name validation error, got: %s", err.Error())
	}
}

// Test uniqueness validation - duplicate item names
func TestSecretsValidator_ValidateStructure_DuplicateItemNames(t *testing.T) {
	v := validator.NewSecretsValidator()

	config := &validator.SecretsConfig{
		Metadata: validator.MetadataSection{
			Profile:            "test_profile",
			DefaultEnvironment: "development",
		},
		Environments: validator.EnvironmentsSection{
			"development": []validator.SecretItem{
				{Name: "DATABASE_URL", Type: "envvar", Entry: "DB1", Key: "Password"},
				{Name: "DATABASE_URL", Type: "envvar", Entry: "DB2", Key: "Password"},
			},
		},
	}

	err := v.ValidateStructure(config)
	if err == nil {
		t.Fatal("Expected error for duplicate item names, got nil")
	}

	if !strings.Contains(err.Error(), "duplicate item name 'DATABASE_URL' found") {
		t.Errorf("Expected duplicate name validation error, got: %s", err.Error())
	}
}

// Test that duplicate entry paths are now allowed for different purposes
func TestSecretsValidator_ValidateStructure_DuplicateEntryPaths(t *testing.T) {
	v := validator.NewSecretsValidator()

	config := &validator.SecretsConfig{
		Metadata: validator.MetadataSection{
			Profile:            "test_profile",
			DefaultEnvironment: "development",
		},
		Environments: validator.EnvironmentsSection{
			"development": []validator.SecretItem{
				{Name: "DB_PASSWORD_ENV", Type: "envvar", Entry: "DATABASE_URL", Key: "Password"},
				{Name: "DB_PASSWORD_TEXT", Type: "text", Entry: "/DATABASE_URL", Key: "Password"}, // Same entry+key, different purpose
				{Name: "DB_USERNAME", Type: "envvar", Entry: "DATABASE_URL", Key: "UserName"},     // Same entry, different key
			},
		},
	}

	err := v.ValidateStructure(config)
	if err != nil {
		t.Fatalf("Expected no error for allowed duplicate entry paths, got: %s", err.Error())
	}
}

// Test default environment validation - non-existent default environment
func TestSecretsValidator_ValidateStructure_NonExistentDefaultEnvironment(t *testing.T) {
	v := validator.NewSecretsValidator()

	config := &validator.SecretsConfig{
		Metadata: validator.MetadataSection{
			Profile:            "test_profile",
			DefaultEnvironment: "production",
		},
		Environments: validator.EnvironmentsSection{
			"development": []validator.SecretItem{
				{Name: "TEST", Type: "envvar", Entry: "TEST", Key: "Password"},
			},
		},
	}

	err := v.ValidateStructure(config)
	if err == nil {
		t.Fatal("Expected error for non-existent default environment, got nil")
	}

	if !strings.Contains(err.Error(), "default_environment 'production' does not exist in environments section") {
		t.Errorf("Expected non-existent default environment validation error, got: %s", err.Error())
	}
}
