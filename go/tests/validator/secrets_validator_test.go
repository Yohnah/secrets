package validator_test

import (
	"fmt"
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
		{"Valid With Outputs", "valid_with_outputs.yml"},
		{"Valid With Custom Output", "valid_with_custom_output.yml"},
		{"Valid With New Output Formats", "valid_with_outputs_new_formats.yml"},
		{"Valid With Volumes", "valid_with_volumes.yml"},
		{"Valid Empty Volumes", "valid_empty_volumes.yml"},
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
		{"Default Environment Not Exists", "invalid_default_env_not_exists.yml", "no longer supported"},
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

environments:
  production:
    - name: "KEY"
      type: "envvar"
      entry: "/A"
      key: "K"

outputs: []

---
metadata:
  profile: "myapp"

environments:
  development:
    - name: "KEY"
      type: "envvar"
      entry: "/B"
      key: "K"

outputs: []
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

environments:
  production:
    - name: "` + tc.itemName + `"
      type: "envvar"
      entry: "/Test"
      key: "Password"

outputs: []
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

environments:
  production:
    - name: "TEST_KEY"
      type: "envvar"
      entry: "` + tc.entryPath + `"
      key: "Password"

outputs: []
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
		{"Valid - sshkey", "sshkey", true},
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

environments:
  production:
    - name: "TEST_KEY"
      entry: "/Test"
      key: "Password"

outputs: []
`
			} else {
				content = `metadata:
  profile: "test"

environments:
  production:
    - name: "TEST_KEY"
      type: "` + tc.itemType + `"
      entry: "/Test"
      key: "Password"

outputs: []
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

// TestReadAndValidateSecretsYML_ValidOutputs tests valid outputs configuration
func TestReadAndValidateSecretsYML_ValidOutputs(t *testing.T) {
	filePath := filepath.Join("testdata", "valid_with_outputs.yml")

	validatorMgr := validator.NewManager()
	config, errors := validatorMgr.ReadAndValidateSecretsYML(filePath)

	if len(errors) > 0 {
		t.Errorf("Expected no errors for valid outputs file, got: %s", formatErrors(errors))
	}

	if config == nil {
		t.Fatal("Expected config to be non-nil")
	}

	if len(config.Profiles) != 1 {
		t.Fatalf("Expected 1 profile, got %d", len(config.Profiles))
	}

	profile := config.Profiles[0]

	// Check that outputs are parsed correctly
	dotenvCount := 0
	dotnetCount := 0
	shellCount := 0
	terraformCount := 0

	for _, output := range profile.Outputs {
		switch output.Format {
		case "dotenv":
			dotenvCount++
		case "dotnet":
			dotnetCount++
		case "shell":
			shellCount++
		case "terraform":
			terraformCount++
		}
	}

	if dotenvCount != 2 {
		t.Errorf("Expected 2 dotenv outputs, got %d", dotenvCount)
	}

	if dotnetCount != 1 {
		t.Errorf("Expected 1 dotnet output, got %d", dotnetCount)
	}

	if shellCount != 2 {
		t.Errorf("Expected 2 shell outputs, got %d", shellCount)
	}

	if terraformCount != 1 {
		t.Errorf("Expected 1 terraform output, got %d", terraformCount)
	}
}

// TestReadAndValidateSecretsYML_InvalidOutputs tests invalid outputs configurations
func TestReadAndValidateSecretsYML_InvalidOutputs(t *testing.T) {
	testCases := []struct {
		name          string
		filename      string
		expectedError string
	}{
		{"Duplicate File", "invalid_outputs_duplicate_file.yml", "duplicate file"},
		{"Environment Not Exists", "invalid_outputs_env_not_exists.yml", "profile 'test-env-not-exists': outputs[0] (file: '.env.staging', format: 'dotenv'): environment 'staging' not found"},
		{"Invalid Format", "invalid_outputs_shell_format.yml", "invalid format"},
		{"Missing Required Fields", "invalid_outputs_missing_fields.yml", "required"},
		{"Invalid Section By", "invalid_outputs_invalid_section_by.yml", "invalid section_by"},
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

// TestReadAndValidateSecretsYML_EmptyOutputs tests that empty outputs are allowed
func TestReadAndValidateSecretsYML_EmptyOutputs(t *testing.T) {
	// Use existing valid file that should have empty outputs
	filePath := filepath.Join("testdata", "valid_single_profile.yml")

	validatorMgr := validator.NewManager()
	config, errors := validatorMgr.ReadAndValidateSecretsYML(filePath)

	if len(errors) > 0 {
		t.Errorf("Expected no errors for file with empty outputs, got: %s", formatErrors(errors))
	}

	if config == nil {
		t.Fatal("Expected config to be non-nil")
	}

	// Empty outputs should be allowed
	if len(config.Profiles) == 0 {
		t.Fatal("Expected at least one profile")
	}
}

// TestReadAndValidateSecretsYML_ValidCustomOutputWithTemplate tests custom output with valid template
func TestReadAndValidateSecretsYML_ValidCustomOutputWithTemplate(t *testing.T) {
	// Create temporary template file for testing
	tmpFile, err := os.CreateTemp("", "test-template-*.tpl")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	templateContent := "# Test template\n{{range .}}\n{{.Name}}={{.Value}}\n{{end}}"
	if _, err := tmpFile.WriteString(templateContent); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Create test YAML file with reference to temp template
	testYAML := fmt.Sprintf(`metadata:
  profile: "test-custom-output-temp"

environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Production/Database"
      key: "Password"

outputs:
  - file: "custom-output.txt"
    environment: "production"
    format: "custom"
    template: "%s"
`, tmpFile.Name())

	// Create temporary YAML file
	tmpYAML, err := os.CreateTemp("", "test-yaml-*.yml")
	if err != nil {
		t.Fatalf("Failed to create temp YAML file: %v", err)
	}
	defer os.Remove(tmpYAML.Name())

	if _, err := tmpYAML.WriteString(testYAML); err != nil {
		t.Fatalf("Failed to write to temp YAML file: %v", err)
	}
	tmpYAML.Close()

	validatorMgr := validator.NewManager()
	config, errors := validatorMgr.ReadAndValidateSecretsYML(tmpYAML.Name())

	if len(errors) > 0 {
		t.Errorf("Expected no errors for valid custom output with template, got: %s", formatErrors(errors))
	}

	if config == nil {
		t.Fatal("Expected config to be non-nil")
	}

	if len(config.Profiles) != 1 {
		t.Fatalf("Expected 1 profile, got %d", len(config.Profiles))
	}

	profile := config.Profiles[0]

	// Find custom output
	var customOutput *validator.OutputItem
	for i := range profile.Outputs {
		if profile.Outputs[i].Format == "custom" {
			customOutput = &profile.Outputs[i]
			break
		}
	}

	if customOutput == nil {
		t.Fatalf("Expected 1 custom output, but not found")
	}

	if customOutput.File != "custom-output.txt" {
		t.Errorf("Expected file 'custom-output.txt', got '%s'", customOutput.File)
	}

	if customOutput.Environment != "production" {
		t.Errorf("Expected environment 'production', got '%s'", customOutput.Environment)
	}

	// For custom format, we don't have Template field in OutputItem yet
	// This test might need adjustment when custom format is fully implemented
}

// TestReadAndValidateSecretsYML_ValidVolumes tests valid volumes configuration
func TestReadAndValidateSecretsYML_ValidVolumes(t *testing.T) {
	filePath := filepath.Join("testdata", "valid_with_volumes.yml")

	validatorMgr := validator.NewManager()
	config, errors := validatorMgr.ReadAndValidateSecretsYML(filePath)

	if len(errors) > 0 {
		t.Errorf("Expected no errors for valid volumes file, got: %s", formatErrors(errors))
	}

	if config == nil {
		t.Fatal("Expected config to be non-nil")
	}

	if len(config.Profiles) != 1 {
		t.Fatalf("Expected 1 profile, got %d", len(config.Profiles))
	}

	profile := config.Profiles[0]

	if len(profile.Volumes) != 2 {
		t.Fatalf("Expected 2 volumes, got %d", len(profile.Volumes))
	}

	// Check first volume
	if profile.Volumes[0].Name != "data-volume" {
		t.Errorf("Expected volume name 'data-volume', got '%s'", profile.Volumes[0].Name)
	}
	if profile.Volumes[0].MountPath != "/var/lib/data" {
		t.Errorf("Expected mount_path '/var/lib/data', got '%s'", profile.Volumes[0].MountPath)
	}
	if profile.Volumes[0].Type != "dir" {
		t.Errorf("Expected type 'dir', got '%s'", profile.Volumes[0].Type)
	}

	// Check second volume
	if profile.Volumes[1].Name != "logs-volume" {
		t.Errorf("Expected volume name 'logs-volume', got '%s'", profile.Volumes[1].Name)
	}
	if profile.Volumes[1].Type != "dir" {
		t.Errorf("Expected type 'dir', got '%s'", profile.Volumes[1].Type)
	}
}

// TestReadAndValidateSecretsYML_InvalidVolumes tests invalid volumes configurations
func TestReadAndValidateSecretsYML_InvalidVolumes(t *testing.T) {
	testCases := []struct {
		name     string
		fileName string
	}{
		{"Missing name", "invalid_volume_missing_name.yml"},
		{"Missing mount_path", "invalid_volume_missing_mount_path.yml"},
		{"Missing type", "invalid_volume_missing_type.yml"},
		{"Invalid mount_path", "invalid_volume_invalid_mount_path.yml"},
		{"Invalid type", "invalid_volume_invalid_type.yml"},
		{"Duplicate names", "invalid_volume_duplicate_names.yml"},
		{"Invalid basedirs reference", "invalid_volume_basedirs_reference.yml"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filePath := filepath.Join("testdata", tc.fileName)

			validatorMgr := validator.NewManager()
			_, errors := validatorMgr.ReadAndValidateSecretsYML(filePath)

			if len(errors) == 0 {
				t.Errorf("Expected errors for %s, but got none", tc.name)
			}
		})
	}
}

// TestReadAndValidateSecretsYML_EmptyVolumes tests that empty volumes are allowed
func TestReadAndValidateSecretsYML_EmptyVolumes(t *testing.T) {
	filePath := filepath.Join("testdata", "valid_empty_volumes.yml")

	validatorMgr := validator.NewManager()
	config, errors := validatorMgr.ReadAndValidateSecretsYML(filePath)

	if len(errors) > 0 {
		t.Errorf("Expected no errors for empty volumes file, got: %s", formatErrors(errors))
	}

	if config == nil {
		t.Fatal("Expected config to be non-nil")
	}

	if len(config.Profiles) != 1 {
		t.Fatalf("Expected 1 profile, got %d", len(config.Profiles))
	}

	profile := config.Profiles[0]

	if len(profile.Volumes) != 0 {
		t.Fatalf("Expected 0 volumes, got %d", len(profile.Volumes))
	}
}
