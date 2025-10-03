// Package secrets provides business logic for secrets management following DDD principles
// This package handles the logic layer between commands and KeePass database operations
package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yohnah/secrets/internal/git"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/validator"
)

// SecretsManager defines the interface for secrets business logic operations
// Following Interface Segregation Principle (ISP) - specific interface for secrets logic
type SecretsManager interface {
	// Secrets.yml file operations (October 3, 2025)
	LoadAndValidateSecretsFile(secretsPath string) (*validator.SecretsConfig, error)
	ProcessSecretsForInit(secretsPath string) error

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
	dbManager  keepass.DatabaseManager
	validator  validator.SecretsValidator
	gitManager git.RepositoryManager
}

// NewSecretsManager creates a new secrets manager
// Following Dependency Inversion Principle (DIP) - returns interface, depends on abstraction
func NewSecretsManager(dbManager keepass.DatabaseManager) SecretsManager {
	return &SecretsBusinessManager{
		dbManager:  dbManager,
		validator:  validator.NewSecretsValidator(),
		gitManager: git.NewRepositoryManager(),
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
	// TODO: Implement when profile validation functions are ready

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

// LoadAndValidateSecretsFile loads and validates a secrets.yml file from the specified path
// Following Single Responsibility Principle - handles file loading and validation
func (m *SecretsBusinessManager) LoadAndValidateSecretsFile(secretsPath string) (*validator.SecretsConfig, error) {
	// Determine the actual file path
	filePath, err := m.resolveSecretsFilePath(secretsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve secrets file path: %w", err)
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("secrets.yml file not found at path: %s", filePath)
	}

	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secrets file '%s': %w", filePath, err)
	}

	// Validate file using validator
	config, err := m.validator.ValidateFile(content)
	if err != nil {
		return nil, fmt.Errorf("file '%s' does not meet format and definition requirements, please correct it: %w", filePath, err)
	}

	return config, nil
}

// ProcessSecretsForInit processes secrets.yml file for init command
// Following Single Responsibility Principle - only validates the secrets file when present
func (m *SecretsBusinessManager) ProcessSecretsForInit(secretsPath string) error {
	// Try to resolve the file path first
	filePath, err := m.resolveSecretsFilePath(secretsPath)
	if err != nil {
		// If we can't resolve path (e.g., not in git repo and no path provided),
		// skip validation for now - this allows init without secrets.yml
		return nil
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// If file doesn't exist, skip validation for now
		// This allows init without requiring secrets.yml to exist
		return nil
	}

	// If file exists, validate it
	_, err = m.LoadAndValidateSecretsFile(secretsPath)
	return err
}

// resolveSecretsFilePath resolves the secrets file path based on input
// Following Single Responsibility Principle - handles path resolution logic
func (m *SecretsBusinessManager) resolveSecretsFilePath(secretsPath string) (string, error) {
	// If no path provided, search in git repository root
	if secretsPath == "" {
		gitRoot, err := m.gitManager.FindGitRoot()
		if err != nil {
			return "", fmt.Errorf("not in a git repository and no secrets file path provided")
		}
		return filepath.Join(gitRoot, "secrets.yml"), nil
	}

	// If path provided, resolve it (could be relative or absolute)
	if filepath.IsAbs(secretsPath) {
		return secretsPath, nil
	}

	// For relative paths, resolve from current directory
	absPath, err := filepath.Abs(secretsPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve relative path '%s': %w", secretsPath, err)
	}

	return absPath, nil
}
