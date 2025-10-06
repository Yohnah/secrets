package validator_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/validator"
)

// Helper function to check if errors contain expected message
func containsErrorWithMessage(errors []error, expectedMsg string) bool {
	expectedLower := strings.ToLower(expectedMsg)
	for _, err := range errors {
		if strings.Contains(strings.ToLower(err.Error()), expectedLower) {
			return true
		}
	}
	return false
}

// Helper function to format multiple errors
func formatErrors(errors []error) string {
	if len(errors) == 0 {
		return "no errors"
	}
	var sb strings.Builder
	for i, err := range errors {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(err.Error())
	}
	return sb.String()
}

// TestReadAndValidateSecretsYML_ValidFiles tests valid secrets.yml files
func TestReadAndValidateSecretsYML_ValidFiles(t *testing.T) {
	testCases := []struct {
		name     string
		filename string
	}{
		{"Valid Single Profile", "valid_single_profile.yml"},
		{"Valid Multiple Profiles", "valid_multiple_profiles.yml"},
		{"Valid All Types", "valid_all_types.yml"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filePath := filepath.Join("testdata", tc.filename)

			validatorMgr := validator.NewManager()
			config, errors := validatorMgr.ReadAndValidateSecretsYML(filePath)

			if len(errors) > 0 {
				t.Errorf("Expected no errors for %s, got: %s", tc.filename, formatErrors(errors))
			}

			if config == nil {
				t.Errorf("Expected config to be non-nil for %s", tc.filename)
			}

			if config != nil && len(config.Profiles) == 0 {
				t.Errorf("Expected at least one profile for %s", tc.filename)
			}
		})
	}
}

// TestReadAndValidateSecretsYML_InvalidFiles tests invalid secrets.yml files
func TestReadAndValidateSecretsYML_InvalidFiles(t *testing.T) {
	testCases := []struct {
		name          string
		filename      string
		expectedError string
	}{
		{"Missing Metadata", "invalid_missing_metadata.yml", "required"},
		{"Duplicate Profiles", "invalid_duplicate_profiles.yml", "duplicate profile"},
		{"Duplicate Environments", "invalid_duplicate_environments.yml", "already defined"},
		{"Duplicate Items", "invalid_duplicate_items.yml", "duplicate item"},
		{"Wrong Type", "invalid_wrong_type.yml", "must be one of"},
		{"Missing Required Field", "invalid_missing_fields.yml", "required"},
		{"Bad Entry Format", "invalid_bad_entry_format.yml", "must start with"},
		{"Bad Item Name", "invalid_bad_item_name.yml", "invalid characters"},
		{"Default Environment Not Exists", "invalid_default_env_not_exists.yml", "does not exist"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filePath := filepath.Join("testdata", tc.filename)

			validatorMgr := validator.NewManager()
			_, errors := validatorMgr.ReadAndValidateSecretsYML(filePath)

			if len(errors) == 0 {
				t.Errorf("Expected error for %s, but got none", tc.filename)
				return
			}

			if !containsErrorWithMessage(errors, tc.expectedError) {
				t.Errorf("Expected error containing '%s' for %s, got: %s",
					tc.expectedError, tc.filename, formatErrors(errors))
			}
		})
	}
}

// TestReadAndValidateSecretsYML_FileNotFound tests non-existent file
func TestReadAndValidateSecretsYML_FileNotFound(t *testing.T) {
	validatorMgr := validator.NewManager()
	_, errors := validatorMgr.ReadAndValidateSecretsYML("nonexistent.yml")

	if len(errors) == 0 {
		t.Error("Expected error for non-existent file")
	}
}

// TestCaseInsensitiveComparison tests that comparisons are case-insensitive
func TestCaseInsensitiveComparison(t *testing.T) {
	// Create a file with duplicate profiles in different cases
	tempFile := filepath.Join(os.TempDir(), "test_case_insensitive.yml")
	content := `metadata:
  profile: "MyApp"
  default_environment: "production"

environments:
  production:
    - name: "KEY"
      type: "envvar"
      entry: "/A"
      key: "K"

outputs: {}

---
metadata:
  profile: "myapp"
  default_environment: "development"

environments:
  development:
    - name: "KEY"
      type: "envvar"
      entry: "/B"
      key: "K"

outputs: {}
`
	err := os.WriteFile(tempFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(tempFile)

	validatorMgr := validator.NewManager()
	_, validationErrors := validatorMgr.ReadAndValidateSecretsYML(tempFile)

	if len(validationErrors) == 0 {
		t.Error("Expected error for duplicate profiles (case-insensitive), got none")
		return
	}

	if !containsErrorWithMessage(validationErrors, "duplicate") {
		t.Errorf("Expected duplicate error, got: %s", formatErrors(validationErrors))
	}
}

// TestErrorAccumulation tests that all errors are accumulated, not fail-fast
func TestErrorAccumulation(t *testing.T) {
	// Create a file with multiple errors
	tempFile := filepath.Join(os.TempDir(), "test_multiple_errors.yml")
	content := `metadata:
  profile: ""
  default_environment: "nonexistent"

environments:
  production:
    - name: "INVALID NAME"
      type: "invalid_type"
      entry: "no_slash"
      key: ""
`
	err := os.WriteFile(tempFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(tempFile)

	validatorMgr := validator.NewManager()
	_, validationErrors := validatorMgr.ReadAndValidateSecretsYML(tempFile)

	if len(validationErrors) == 0 {
		t.Fatal("Expected validation errors, got none")
	}

	// Check that multiple errors are present (error accumulation)
	t.Logf("Validation errors (%d total): %s", len(validationErrors), formatErrors(validationErrors))

	// We expect multiple errors to be reported
	if len(validationErrors) < 2 {
		t.Errorf("Expected multiple errors (error accumulation), got only %d", len(validationErrors))
	}
}

// TestValidItemName tests item name validation
func TestValidItemName(t *testing.T) {
	testCases := []struct {
		name     string
		itemName string
		valid    bool
	}{
		{"Valid - Letters", "DBPASSWORD", true},
		{"Valid - Letters and Numbers", "DB_PASSWORD123", true},
		{"Valid - Underscore", "DB_PASS_WORD", true},
		{"Valid - Hyphen", "DB-PASS-WORD", true},
		{"Valid - Mixed", "DB_PASS-123", true},
		{"Invalid - Space", "DB PASS", false},
		{"Invalid - Special Char @", "DB@PASS", false},
		{"Invalid - Dot", "DB.PASS", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a temporary file with the item name
			tempFile := filepath.Join(os.TempDir(), "test_item_name.yml")
			content := `metadata:
  profile: "test"
  default_environment: "production"

environments:
  production:
    - name: "` + tc.itemName + `"
      type: "envvar"
      entry: "/Test"
      key: "Password"

outputs: {}
`
			err := os.WriteFile(tempFile, []byte(content), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}
			defer os.Remove(tempFile)

			validatorMgr := validator.NewManager()
			_, validationErrors := validatorMgr.ReadAndValidateSecretsYML(tempFile)

			if tc.valid && len(validationErrors) > 0 {
				t.Errorf("Expected valid item name '%s', got errors: %s",
					tc.itemName, formatErrors(validationErrors))
			}

			if !tc.valid && len(validationErrors) == 0 {
				t.Errorf("Expected invalid item name '%s' to fail, but got no errors", tc.itemName)
			}

			if !tc.valid && len(validationErrors) > 0 {
				if !containsErrorWithMessage(validationErrors, "invalid") &&
					!containsErrorWithMessage(validationErrors, "name") {
					t.Errorf("Expected name validation error for '%s', got: %s",
						tc.itemName, formatErrors(validationErrors))
				}
			}
		})
	}
}

// TestEntryPathValidation tests entry path format validation
func TestEntryPathValidation(t *testing.T) {
	testCases := []struct {
		name      string
		entryPath string
		valid     bool
	}{
		{"Valid - Root Entry", "/Entry", true},
		{"Valid - Nested Entry", "/Group1/Group2/Entry", true},
		{"Valid - Deep Nesting", "/L1/L2/L3/L4/Entry", true},
		{"Invalid - No Leading Slash", "Entry", false},
		{"Invalid - Just Slash", "/", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tempFile := filepath.Join(os.TempDir(), "test_entry_path.yml")
			content := `metadata:
  profile: "test"
  default_environment: "production"

environments:
  production:
    - name: "TEST_KEY"
      type: "envvar"
      entry: "` + tc.entryPath + `"
      key: "Password"

outputs: {}
`
			err := os.WriteFile(tempFile, []byte(content), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}
			defer os.Remove(tempFile)

			validatorMgr := validator.NewManager()
			_, validationErrors := validatorMgr.ReadAndValidateSecretsYML(tempFile)

			if tc.valid && len(validationErrors) > 0 {
				t.Errorf("Expected valid entry path '%s', got errors: %s",
					tc.entryPath, formatErrors(validationErrors))
			}

			if !tc.valid && len(validationErrors) == 0 {
				t.Errorf("Expected invalid entry path '%s' to fail, but got no errors", tc.entryPath)
			}

			if !tc.valid && len(validationErrors) > 0 {
				if !containsErrorWithMessage(validationErrors, "entry") {
					t.Errorf("Expected entry validation error for '%s', got: %s",
						tc.entryPath, formatErrors(validationErrors))
				}
			}
		})
	}
}

// TestTypeValidation tests type field validation
func TestTypeValidation(t *testing.T) {
	testCases := []struct {
		name     string
		itemType string
		valid    bool
	}{
		{"Valid - envvar", "envvar", true},
		{"Valid - text", "text", true},
		{"Valid - ssh_agent", "ssh_agent", true},
		{"Invalid - wrong_type", "wrong_type", false},
		{"Invalid - empty", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tempFile := filepath.Join(os.TempDir(), "test_type.yml")
			var content string

			if tc.itemType == "" {
				// For empty test, omit the type field entirely
				content = `metadata:
  profile: "test"
  default_environment: "production"

environments:
  production:
    - name: "TEST_KEY"
      entry: "/Test"
      key: "Password"

outputs: {}
`
			} else {
				content = `metadata:
  profile: "test"
  default_environment: "production"

environments:
  production:
    - name: "TEST_KEY"
      type: "` + tc.itemType + `"
      entry: "/Test"
      key: "Password"

outputs: {}
`
			}

			err := os.WriteFile(tempFile, []byte(content), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}
			defer os.Remove(tempFile)

			validatorMgr := validator.NewManager()
			_, validationErrors := validatorMgr.ReadAndValidateSecretsYML(tempFile)

			if tc.valid && len(validationErrors) > 0 {
				t.Errorf("Expected valid type '%s', got errors: %s",
					tc.itemType, formatErrors(validationErrors))
			}

			if !tc.valid && len(validationErrors) == 0 {
				t.Errorf("Expected invalid type '%s' to fail, but got no errors", tc.itemType)
			}

			if !tc.valid && len(validationErrors) > 0 {
				if !containsErrorWithMessage(validationErrors, "type") {
					t.Errorf("Expected type validation error for '%s', got: %s",
						tc.itemType, formatErrors(validationErrors))
				}
			}
		})
	}
}
