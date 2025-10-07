package validator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ValidatorManager defines the interface for validation operations
type ValidatorManager interface {
	ValidateConfigFile(filePath string) error
	ValidateTemplate(templateContent string) error
	ReadAndValidateSecretsYML(filePath string) (*SecretsConfig, []error)
	ValidateKeePassDuplicates(db KeePassManager) []error
	ValidateNoDuplicateEntries(envName string, entryPaths []string) error

	// Fail-fast validation methods for KeePass operations
	ValidateUniqueProfileInRoot(profiles []string, profileName string) error
	ValidateUniqueEntryInPath(entries []string, entryName string, fullPath string) error
	ValidateUniqueFieldsInEntry(fields []string, entryPath string) error
}

// manager implements the ValidatorManager interface
type manager struct{}

// NewManager creates a new instance of ValidatorManager
func NewManager() ValidatorManager {
	return &manager{}
}

// ValidateConfigFile validates the structure and content of a config.yml file
func (m *manager) ValidateConfigFile(filePath string) error {
	// Read file content
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML into a map to detect unknown fields
	var rawConfig map[string]interface{}
	if err := yaml.Unmarshal(data, &rawConfig); err != nil {
		return fmt.Errorf("invalid YAML format: %w", err)
	}

	// Define known fields
	knownFields := map[string]bool{
		"database":           true,
		"keyfile":            true,
		"no_create_database": true,
	}

	// Check for unknown fields
	for field := range rawConfig {
		if !knownFields[field] {
			return fmt.Errorf("unknown field in config file: '%s'", field)
		}
	}

	// Validate required fields
	if _, exists := rawConfig["database"]; !exists {
		return fmt.Errorf("required field 'database' is missing")
	}
	if _, exists := rawConfig["keyfile"]; !exists {
		return fmt.Errorf("required field 'keyfile' is missing")
	}

	// Validate field types
	if database, ok := rawConfig["database"].(string); !ok {
		return fmt.Errorf("field 'database' must be a string")
	} else if err := validatePathFormat(database); err != nil {
		return fmt.Errorf("invalid 'database' path: %w", err)
	}

	if keyfile, ok := rawConfig["keyfile"].(string); !ok {
		return fmt.Errorf("field 'keyfile' must be a string")
	} else if err := validatePathFormat(keyfile); err != nil {
		return fmt.Errorf("invalid 'keyfile' path: %w", err)
	}

	// Validate no_create_database (optional field)
	if noCreateDB, exists := rawConfig["no_create_database"]; exists {
		if _, ok := noCreateDB.(bool); !ok {
			return fmt.Errorf("field 'no_create_database' must be a boolean")
		}
	}

	return nil
}

// ValidateTemplate validates the structure and content of a template
func (m *manager) ValidateTemplate(templateContent string) error {
	if templateContent == "" {
		return fmt.Errorf("template content is empty")
	}

	// Check for required template variables
	requiredVars := []string{
		"{{.Database}}",
		"{{.Keyfile}}",
		"{{.NoCreateDatabaseLine}}",
	}

	for _, requiredVar := range requiredVars {
		if !strings.Contains(templateContent, requiredVar) {
			return fmt.Errorf("template is missing required variable: %s", requiredVar)
		}
	}

	// Basic syntax validation - check for balanced braces
	openBraces := strings.Count(templateContent, "{{")
	closeBraces := strings.Count(templateContent, "}}")
	if openBraces != closeBraces {
		return fmt.Errorf("template has unbalanced braces: %d opening vs %d closing", openBraces, closeBraces)
	}

	return nil
}

// validatePathFormat validates that a path has a valid format
// It accepts both absolute and relative paths
// It does NOT check if the file/directory exists
func validatePathFormat(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	// Clean the path to normalize it
	cleanPath := filepath.Clean(path)

	// Check for invalid characters (basic validation)
	// This is platform-independent basic check
	invalidChars := []string{"\x00", "\n", "\r"}
	for _, char := range invalidChars {
		if strings.Contains(path, char) {
			return fmt.Errorf("path contains invalid characters")
		}
	}

	// Check if path looks reasonable (not just whitespace)
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("path cannot be only whitespace")
	}

	// Accept both absolute and relative paths
	// filepath.IsAbs is platform-aware
	_ = filepath.IsAbs(cleanPath) // Just validate it's processable

	return nil
}

// ValidateUniqueProfileInRoot checks if there are duplicate profiles with the given name in ROOT
// Returns error immediately if duplicates found (fail-fast)
func (m *manager) ValidateUniqueProfileInRoot(profiles []string, profileName string) error {
	// Normalize profile name for comparison (case-insensitive)
	normalizedTarget := strings.ToLower(normalizeString(profileName))

	// Count occurrences
	count := 0
	for _, p := range profiles {
		if strings.ToLower(normalizeString(p)) == normalizedTarget {
			count++
		}
	}

	if count > 1 {
		return fmt.Errorf("database corruption: found %d profiles named '%s' in ROOT. Each profile must be unique. Please fix manually using a KeePass client", count, profileName)
	}

	return nil
}

// ValidateUniqueEntryInPath checks if there are duplicate entries with the given name at the path
// Returns error immediately if duplicates found (fail-fast)
func (m *manager) ValidateUniqueEntryInPath(entries []string, entryName string, fullPath string) error {
	// Normalize entry name for comparison (case-insensitive)
	normalizedTarget := strings.ToLower(normalizeString(entryName))

	// Count occurrences
	count := 0
	for _, e := range entries {
		if strings.ToLower(normalizeString(e)) == normalizedTarget {
			count++
		}
	}

	// If more than one occurrence, it's a duplicate
	if count > 1 {
		return fmt.Errorf("database corruption: found %d entries named '%s' at path '%s'. Each entry path must be unique. Please fix manually using a KeePass client",
			count, entryName, fullPath)
	}

	return nil
}

// ValidateUniqueFieldsInEntry checks if there are duplicate fields in the entry
// Considers case-insensitivity for standard KeePass fields (Title, UserName, Password, URL, Notes)
// Returns error immediately if duplicates found (fail-fast)
func (m *manager) ValidateUniqueFieldsInEntry(fields []string, entryPath string) error {
	// Standard KeePass fields (case-insensitive)
	standardFields := map[string]bool{
		"title":    true,
		"username": true,
		"password": true,
		"url":      true,
		"notes":    true,
	}

	// Track seen fields
	standardSeen := make(map[string]string) // normalized -> original
	customSeen := make(map[string]string)   // normalized -> original

	for _, field := range fields {
		// Normalize first (trim spaces), then lowercase for standard field check
		normalized := normalizeString(field)
		fieldLower := strings.ToLower(normalized)

		// Check if it's a standard field (case-insensitive after normalization)
		if standardFields[fieldLower] {
			if original, exists := standardSeen[fieldLower]; exists {
				return fmt.Errorf("database corruption: found duplicate standard field '%s' (case-insensitive, also found as '%s') in entry at '%s'. Each field must be unique. Please fix manually using a KeePass client",
					field, original, entryPath)
			}
			standardSeen[fieldLower] = field
		} else {
			// Custom field (case-sensitive, but still normalized for spaces)
			if _, exists := customSeen[normalized]; exists {
				return fmt.Errorf("database corruption: found duplicate custom field '%s' (case-sensitive) in entry at '%s'. Each field must be unique. Please fix manually using a KeePass client",
					field, entryPath)
			}
			customSeen[normalized] = field
		}
	}

	return nil
}

// normalizeString normalizes a string for comparison (trim spaces)
func normalizeString(s string) string {
	return strings.TrimSpace(s)
}

// ValidateNoDuplicateEntries validates that there are no duplicate entry paths
// within the specified environment and profile. This is crucial to detect BBDD
// corruption where multiple items in secrets.yml map to the same entry path.
func (m *manager) ValidateNoDuplicateEntries(envName string, entryPaths []string) error {
	// Check for duplicates using a map
	seen := make(map[string]bool)
	var duplicates []string

	for _, path := range entryPaths {
		if seen[path] {
			duplicates = append(duplicates, path)
		} else {
			seen[path] = true
		}
	}

	// If duplicates found, return detailed error
	if len(duplicates) > 0 {
		return fmt.Errorf("BBDD corruption detected: duplicate entry paths found in environment '%s': %v", envName, duplicates)
	}

	return nil
}
