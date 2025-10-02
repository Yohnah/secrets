// Package secrets provides business logic for secrets management following DDD principles
// This package handles the logic layer between commands and KeePass database operations
package secrets

import (
	"fmt"
	"strings"

	"github.com/Yohnah/secrets/internal/keepass"
)

// SecretsManager defines the interface for secrets business logic operations
// Following Interface Segregation Principle (ISP) - specific interface for secrets logic
type SecretsManager interface {
	// Profile and HEAD management
	ValidateProfileUniqueness(profileName string) error
	EnsureProfileStructure(profileName string) error

	// Environment management
	ValidateEnvironmentUniqueness(profileName string, environments []string) error
	CreateEnvironments(profileName string, environments []string) error

	// Item management and validation
	ValidateItemUniqueness(profileName, environment string, items []SecretItem) error
	ValidateItemStructure(items []SecretItem) error
	CreateItems(profileName, environment string, items []SecretItem) error

	// Secrets.yml integration
	ValidateSecretsFile(secretsData *SecretsData) error
	SyncSecretsToDatabase(secretsData *SecretsData) error
}

// SecretsBusinessManager implements SecretsManager
// Following Single Responsibility Principle (SRP) - handles secrets business logic
type SecretsBusinessManager struct {
	dbManager keepass.DatabaseManager
}

// NewSecretsManager creates a new secrets manager
// Following Dependency Inversion Principle (DIP) - returns interface, depends on abstraction
func NewSecretsManager(dbManager keepass.DatabaseManager) SecretsManager {
	return &SecretsBusinessManager{
		dbManager: dbManager,
	}
}

// SecretsData represents the complete secrets.yml structure
type SecretsData struct {
	Metadata     Metadata                `yaml:"metadata"`
	Environments map[string][]SecretItem `yaml:"environments"`
}

// Metadata represents the metadata section of secrets.yml
type Metadata struct {
	Profile            string `yaml:"profile"`
	DefaultEnvironment string `yaml:"default_environment"`
}

// SecretItem represents an item in an environment
type SecretItem struct {
	Name  string `yaml:"name"`
	Entry string `yaml:"entry"`
	Key   string `yaml:"key"`
	Type  string `yaml:"type"`
}

// ValidateProfileUniqueness ensures only one profile with the given name exists in KeePass root
func (m *SecretsBusinessManager) ValidateProfileUniqueness(profileName string) error {
	// TODO: Implement logic to check KeePass root for duplicate profile groups
	// This should throw an exception if duplicates are found
	return fmt.Errorf("ValidateProfileUniqueness not implemented yet")
}

// EnsureProfileStructure creates profile and HEAD structure if they don't exist
func (m *SecretsBusinessManager) EnsureProfileStructure(profileName string) error {
	// TODO: Implement logic to create profile → HEAD structure
	// 1. Create profile group in root if it doesn't exist
	// 2. Create HEAD group under profile if it doesn't exist
	return fmt.Errorf("EnsureProfileStructure not implemented yet")
}

// ValidateEnvironmentUniqueness ensures no duplicate environment names per profile
func (m *SecretsBusinessManager) ValidateEnvironmentUniqueness(profileName string, environments []string) error {
	// Check for duplicates in the provided environments slice
	seen := make(map[string]bool)
	for _, env := range environments {
		if seen[env] {
			return fmt.Errorf("duplicate environment name '%s' found in profile '%s'", env, profileName)
		}
		seen[env] = true
	}

	// TODO: Also check against existing environments in KeePass database
	return nil
}

// CreateEnvironments creates environment groups under profile/HEAD
func (m *SecretsBusinessManager) CreateEnvironments(profileName string, environments []string) error {
	// TODO: Implement logic to create environment groups under profile/HEAD
	return fmt.Errorf("CreateEnvironments not implemented yet")
}

// ValidateItemUniqueness ensures no duplicate item names per environment
func (m *SecretsBusinessManager) ValidateItemUniqueness(profileName, environment string, items []SecretItem) error {
	seen := make(map[string]bool)
	for _, item := range items {
		if seen[item.Name] {
			return fmt.Errorf("duplicate item name '%s' found in environment '%s' of profile '%s'",
				item.Name, environment, profileName)
		}
		seen[item.Name] = true
	}

	// TODO: Also check against existing items in KeePass database
	return nil
}

// ValidateItemStructure validates the structure and content of items
func (m *SecretsBusinessManager) ValidateItemStructure(items []SecretItem) error {
	validTypes := map[string]bool{
		"envvar":    true,
		"text":      true,
		"ssh_agent": true,
	}

	for _, item := range items {
		// Validate type
		if !validTypes[item.Type] {
			return fmt.Errorf("invalid type '%s' for item '%s'. Valid types: envvar, text, ssh_agent",
				item.Type, item.Name)
		}

		// Validate required fields
		if item.Name == "" {
			return fmt.Errorf("item name cannot be empty")
		}
		if item.Entry == "" {
			return fmt.Errorf("item entry cannot be empty for item '%s'", item.Name)
		}
		if item.Key == "" {
			return fmt.Errorf("item key cannot be empty for item '%s'", item.Name)
		}
	}

	return nil
}

// CreateItems creates entries and fields in KeePass database based on items
func (m *SecretsBusinessManager) CreateItems(profileName, environment string, items []SecretItem) error {
	// TODO: Implement logic to:
	// 1. Parse entry paths and create intermediate groups if needed
	// 2. Create entries in appropriate locations
	// 3. Handle standard fields, custom fields, and attachments based on key field
	// 4. Use KeePassManager for all database operations
	return fmt.Errorf("CreateItems not implemented yet")
}

// ValidateSecretsFile validates the complete secrets.yml structure
func (m *SecretsBusinessManager) ValidateSecretsFile(secretsData *SecretsData) error {
	// Validate metadata
	if secretsData.Metadata.Profile == "" {
		return fmt.Errorf("profile cannot be empty in metadata section")
	}
	if secretsData.Metadata.DefaultEnvironment == "" {
		return fmt.Errorf("default_environment cannot be empty in metadata section")
	}

	// Collect all environment names
	envNames := make([]string, 0, len(secretsData.Environments))
	for envName := range secretsData.Environments {
		envNames = append(envNames, envName)
	}

	// Validate environment uniqueness
	if err := m.ValidateEnvironmentUniqueness(secretsData.Metadata.Profile, envNames); err != nil {
		return err
	}

	// Validate default environment exists
	if _, exists := secretsData.Environments[secretsData.Metadata.DefaultEnvironment]; !exists {
		return fmt.Errorf("default_environment '%s' does not exist in environments section",
			secretsData.Metadata.DefaultEnvironment)
	}

	// Validate each environment's items
	for envName, items := range secretsData.Environments {
		if err := m.ValidateItemUniqueness(secretsData.Metadata.Profile, envName, items); err != nil {
			return err
		}
		if err := m.ValidateItemStructure(items); err != nil {
			return fmt.Errorf("error in environment '%s': %v", envName, err)
		}
	}

	return nil
}

// SyncSecretsToDatabase synchronizes secrets.yml content with KeePass database
func (m *SecretsBusinessManager) SyncSecretsToDatabase(secretsData *SecretsData) error {
	// Validate profile uniqueness
	if err := m.ValidateProfileUniqueness(secretsData.Metadata.Profile); err != nil {
		return err
	}

	// Ensure profile structure exists
	if err := m.EnsureProfileStructure(secretsData.Metadata.Profile); err != nil {
		return err
	}

	// Create environments
	envNames := make([]string, 0, len(secretsData.Environments))
	for envName := range secretsData.Environments {
		envNames = append(envNames, envName)
	}
	if err := m.CreateEnvironments(secretsData.Metadata.Profile, envNames); err != nil {
		return err
	}

	// Create items for each environment
	for envName, items := range secretsData.Environments {
		if err := m.CreateItems(secretsData.Metadata.Profile, envName, items); err != nil {
			return fmt.Errorf("error creating items for environment '%s': %v", envName, err)
		}
	}

	return nil
}

// Helper function to parse entry path into groups and entry name
func ParseEntryPath(entryPath string) (groups []string, entryName string) {
	// Remove leading slash if present
	cleanPath := strings.TrimPrefix(entryPath, "/")

	// Split by '/' to get path components
	parts := strings.Split(cleanPath, "/")

	if len(parts) == 1 {
		// Simple entry name, no groups
		return []string{}, parts[0]
	}

	// Last part is entry name, rest are groups
	return parts[:len(parts)-1], parts[len(parts)-1]
}

// Helper function to determine if a key is a standard KeePass field
func IsStandardKeePassField(key string) (bool, string) {
	standardFields := map[string]string{
		"username": "UserName",
		"title":    "Title",
		"url":      "URL",
		"password": "Password",
		"notes":    "Notes",
	}

	standardName, exists := standardFields[strings.ToLower(key)]
	return exists, standardName
}

// Helper function to check if key is an attachment
func IsAttachment(key string) (bool, string) {
	if strings.HasPrefix(key, "attachments/") {
		attachmentName := strings.TrimPrefix(key, "attachments/")
		return true, attachmentName
	}
	return false, ""
}
