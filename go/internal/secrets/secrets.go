// Package secrets provides business logic for secrets management following DDD principles
// This package handles the logic layer between commands and KeePass database operations
package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Yohnah/secrets/internal/git"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/validator"
	"github.com/tobischo/gokeepasslib/v3"
)

// SecretsManager defines the interface for secrets business logic operations
// Following Interface Segregation Principle (ISP) - specific interface for secrets logic
type SecretsManager interface {
	// Secrets.yml file operations (October 3, 2025)
	LoadAndValidateSecretsFile(secretsPath string) (*validator.SecretsConfig, error)
	ProcessSecretsForInit(secretsPath string) error

	// Profile and structure management (October 3, 2025)
	EnsureProfileStructure(dbPath, keyfilePath, password, profileName string, environments map[string][]SecretItem) (*ProfileStructureResult, error)

	// Environment management
	ValidateEnvironmentUniqueness(profileName string, environments []string) error
	CreateEnvironments(profileName string, environments []string) error

	// Item management and validation
	ValidateItemUniqueness(profileName, environment string, items []SecretItem) error
	ValidateItemStructure(items []SecretItem) error
	CreateItems(profileName, environment string, items []SecretItem) error

	// Field population and validation (October 3, 2025)
	PopulateEntryFields(entry *gokeepasslib.Entry, entryName string, items []SecretItem) (int, error)
	IsEntryMatchForItem(entry *gokeepasslib.Entry, item SecretItem) bool

	// Attachment management (October 3, 2025)
	PopulateEntryAttachments(db *gokeepasslib.Database, entry *gokeepasslib.Entry, entryName string, items []SecretItem) (int, error)

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
	logger     logger.Logger
}

// NewSecretsManager creates a new secrets manager
// Following Dependency Inversion Principle (DIP) - returns interface, depends on abstraction
func NewSecretsManager(dbManager keepass.DatabaseManager, log logger.Logger) SecretsManager {
	return &SecretsBusinessManager{
		dbManager:  dbManager,
		validator:  validator.NewSecretsValidator(),
		gitManager: git.NewRepositoryManager(),
		logger:     log,
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

// ProfileStructureResult represents the result of profile structure operations
type ProfileStructureResult struct {
	ProfileCreated      bool
	HeadCreated         bool
	ProfileName         string
	EnvironmentsCreated []string
	EnvironmentsExisted []string
	EntriesCreated      []string
	EntriesExisted      []string
	FieldsAdded         int // Number of fields added to existing entries
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
	// This method will be called from EnsureProfileStructure after HEAD is ensured
	// The database should already be open and HEAD should exist
	return fmt.Errorf("CreateEnvironments should be called through EnsureProfileStructure, not directly")
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

// PopulateEntryFields populates the specified key/field in an entry with default content
// Following CRITICAL SECURITY RULE: validates field uniqueness before any operations
// Returns the number of fields added for tracking database changes
func (m *SecretsBusinessManager) PopulateEntryFields(entry *gokeepasslib.Entry, entryName string, items []SecretItem) (int, error) {
	// First validate existing field uniqueness before any modifications
	if err := ValidateEntryFieldUniqueness(entry, entryName); err != nil {
		return 0, err
	}

	fieldsAdded := []string{}

	// Process each item that references this entry
	for _, item := range items {
		// Skip if this item doesn't reference this entry
		if !m.IsEntryMatchForItem(entry, item) {
			continue
		}

		// Skip attachments - they are handled by PopulateEntryAttachments
		if m.isAttachmentField(item.Key) {
			continue
		}

		// Check if the field already exists to prevent duplicates
		fieldExists := false
		for _, value := range entry.Values {
			if value.Key == item.Key {
				fieldExists = true
				break
			}
		}

		// Only add field if it doesn't exist (prevents duplicates)
		if !fieldExists {
			m.dbManager.SetEntryField(entry, item.Key, "Content pending to be provided by user")
			fieldsAdded = append(fieldsAdded, item.Key)
		}
	}

	// Report fields that were added (verbose mode only)
	if len(fieldsAdded) > 0 {
		m.logger.Info(fmt.Sprintf("Added fields to entry '%s': %s", entryName, strings.Join(fieldsAdded, ", ")))
	}

	// Validate field uniqueness after modifications to ensure no duplicates were introduced
	if err := ValidateEntryFieldUniqueness(entry, entryName); err != nil {
		return 0, err
	}

	return len(fieldsAdded), nil
}

// isAttachmentField checks if a key represents an attachment field
func (m *SecretsBusinessManager) isAttachmentField(key string) bool {
	return strings.HasPrefix(key, "attachments/")
}

// PopulateEntryAttachments creates file attachments for the specified entry based on items
// Returns the number of attachments added and any error
func (m *SecretsBusinessManager) PopulateEntryAttachments(db *gokeepasslib.Database, entry *gokeepasslib.Entry, entryName string, items []SecretItem) (int, error) {
	attachmentsAdded := []string{}

	for _, item := range items {
		// Only process items that match this entry and are attachment fields
		if !m.IsEntryMatchForItem(entry, item) {
			continue
		}

		// Only process attachment fields
		if !m.isAttachmentField(item.Key) {
			continue
		}

		// Extract attachment filename from "attachments/filename" format
		filename := strings.TrimPrefix(item.Key, "attachments/")
		if filename == "" {
			continue // Skip empty filenames
		}

		// Check if attachment already exists to prevent duplicates
		if m.dbManager.HasAttachment(entry, filename) {
			continue // Skip existing attachments
		}

		// Create attachment with placeholder content
		defaultContent := []byte("Attachment content pending to be provided by user")
		err := m.dbManager.AddAttachment(db, entry, filename, defaultContent)
		if err != nil {
			return 0, fmt.Errorf("failed to add attachment '%s' to entry '%s': %w", filename, entryName, err)
		}

		attachmentsAdded = append(attachmentsAdded, filename)
	}

	// Log attachment additions if verbose mode is enabled
	if len(attachmentsAdded) > 0 && m.logger != nil {
		m.logger.Info(fmt.Sprintf("Added attachments to entry '%s': %s", entryName, strings.Join(attachmentsAdded, ", ")))
	}

	return len(attachmentsAdded), nil
}

// IsEntryMatchForItem checks if an entry matches the item's entry path specification
func (m *SecretsBusinessManager) IsEntryMatchForItem(entry *gokeepasslib.Entry, item SecretItem) bool {
	// Extract entry name from item.Entry path
	entryName := item.Entry
	if strings.Contains(item.Entry, "/") {
		parts := strings.Split(strings.TrimPrefix(item.Entry, "/"), "/")
		entryName = parts[len(parts)-1]
	}

	// Compare with entry title
	for _, value := range entry.Values {
		if value.Key == "Title" && value.Value.Content == entryName {
			return true
		}
	}

	return false
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

// ValidateEntryFieldUniqueness validates that no duplicate fields exist in an entry
// Following CRITICAL SECURITY RULE: field duplicates are never tolerated
func ValidateEntryFieldUniqueness(entry *gokeepasslib.Entry, entryName string) error {
	fieldCounts := make(map[string]int)

	// Count occurrences of each field key
	for _, value := range entry.Values {
		fieldCounts[value.Key]++
	}

	// Check for duplicates
	for fieldKey, count := range fieldCounts {
		if count > 1 {
			return fmt.Errorf("duplicate field detected: '%s' found %d times in entry '%s'. Please correct manually in KeePass database", fieldKey, count, entryName)
		}
	}

	return nil
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

// EnsureProfileStructure ensures the profile and HEAD structure exists in the KeePass database
// Following Single Responsibility Principle - handles profile structure business logic
func (m *SecretsBusinessManager) EnsureProfileStructure(dbPath, keyfilePath, password, profileName string, environments map[string][]SecretItem) (*ProfileStructureResult, error) {
	// Validate profile name
	if profileName == "" {
		return nil, fmt.Errorf("profile name cannot be empty")
	}

	// Open the database
	db, err := m.dbManager.OpenDatabase(dbPath, keyfilePath, password)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Find groups with the profile name in root level
	profileGroups, err := m.dbManager.FindGroupsByName(db, profileName)
	if err != nil {
		return nil, fmt.Errorf("failed to search for profile groups: %w", err)
	}

	// Validate business rule: only ONE profile group allowed
	if len(profileGroups) > 1 {
		return nil, fmt.Errorf("profile validation failed: found %d groups with name '%s' in database root, only one is allowed. Please clean duplicate profiles manually", len(profileGroups), profileName)
	}

	var profileGroup *gokeepasslib.Group
	var profileCreated, headCreated bool

	// If profile doesn't exist, create it
	if len(profileGroups) == 0 {
		// Get the SECRETS YOHNAH group (first group in database)
		if len(db.Content.Root.Groups) == 0 {
			return nil, fmt.Errorf("database has no root groups")
		}
		secretsYonahGroup := &db.Content.Root.Groups[0] // This should be "SECRETS YOHNAH"

		// Create profile group under SECRETS YOHNAH
		profileGroup = m.dbManager.CreateGroup(secretsYonahGroup, profileName)
		profileCreated = true
	} else {
		// Profile exists, use it
		profileGroup = profileGroups[0]
		profileCreated = false
	}

	// Check if HEAD group exists within the profile
	var headGroup *gokeepasslib.Group
	headExists := false
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == "HEAD" {
			headGroup = &profileGroup.Groups[i]
			headExists = true
			break
		}
	}

	// Create HEAD group if it doesn't exist
	if !headExists {
		headGroup = m.dbManager.CreateGroup(profileGroup, "HEAD")
		headCreated = true

		// When HEAD is created for the first time, create "Profile metadata" entry
		metadataEntry := m.dbManager.CreateEntry(headGroup, "Profile metadata")

		// Set version field (always starts with 1)
		m.dbManager.SetEntryField(metadataEntry, "version", "1")

		// Set since field with current timestamp
		currentTime := time.Now().Format("2006-01-02 15:04:05")
		m.dbManager.SetEntryField(metadataEntry, "since", currentTime)
	} else {
		headCreated = false
	}

	// Create/verify environments under HEAD
	var environmentsCreated, environmentsExisted []string
	if len(environments) > 0 {
		// Extract environment names
		envNames := make([]string, 0, len(environments))
		for envName := range environments {
			envNames = append(envNames, envName)
		}

		environmentsCreated, environmentsExisted, err = m.ensureEnvironmentsInHead(db, headGroup, envNames)
		if err != nil {
			return nil, fmt.Errorf("failed to ensure environments: %w", err)
		}
	}

	// Create/verify entries in environments
	var entriesCreated, entriesExisted []string
	var totalFieldsAdded int
	if len(environments) > 0 {
		entriesCreated, entriesExisted, totalFieldsAdded, err = m.ensureItemsInEnvironments(db, headGroup, environments)
		if err != nil {
			return nil, fmt.Errorf("failed to ensure entries: %w", err)
		}
	}

	// Save the database only if changes were made
	changesMade := profileCreated || headCreated || len(environmentsCreated) > 0 || len(entriesCreated) > 0 || totalFieldsAdded > 0
	if changesMade {
		if err := m.dbManager.SaveDatabase(db, dbPath); err != nil {
			return nil, fmt.Errorf("failed to save database: %w", err)
		}
	}

	// Return result with information about what was created
	result := &ProfileStructureResult{
		ProfileCreated:      profileCreated,
		HeadCreated:         headCreated,
		ProfileName:         profileName,
		EnvironmentsCreated: environmentsCreated,
		EnvironmentsExisted: environmentsExisted,
		EntriesCreated:      entriesCreated,
		EntriesExisted:      entriesExisted,
		FieldsAdded:         totalFieldsAdded,
	}

	return result, nil
} // ensureEnvironmentsInHead creates missing environment groups under HEAD
// Following Single Responsibility Principle - handles environment creation logic
func (m *SecretsBusinessManager) ensureEnvironmentsInHead(db *gokeepasslib.Database, headGroup *gokeepasslib.Group, environments []string) ([]string, []string, error) {
	var environmentsCreated []string
	var environmentsExisted []string

	for _, envName := range environments {
		// Check if environment already exists in HEAD
		existingEnvs, err := m.dbManager.FindGroupsByNameInParent(headGroup, envName)
		if err != nil {
			return environmentsCreated, environmentsExisted, fmt.Errorf("failed to search for environment '%s': %w", envName, err)
		}

		// CRITICAL SECURITY: Validate environment uniqueness
		if len(existingEnvs) > 1 {
			return nil, nil, fmt.Errorf("duplicate environment detected: '%s' found %d times in profile/HEAD. Please correct manually in KeePass database", envName, len(existingEnvs))
		}

		if len(existingEnvs) > 0 {
			// Environment already exists
			environmentsExisted = append(environmentsExisted, envName)
		} else {
			// Create environment group
			m.dbManager.CreateGroup(headGroup, envName)
			environmentsCreated = append(environmentsCreated, envName)
		}
	}

	return environmentsCreated, environmentsExisted, nil
}

// parseEntryPath parses an entry path into groups and entry name
// Following Single Responsibility Principle - handles entry path parsing logic
func parseEntryPath(entryPath string) ([]string, string) {
	// Remove leading slash if present - "/VAULT_TOKEN" becomes "VAULT_TOKEN"
	cleanPath := strings.TrimPrefix(entryPath, "/")

	// If no path separators, entry goes directly in environment
	if !strings.Contains(cleanPath, "/") {
		return []string{}, cleanPath
	}

	// Split by '/' to get path components
	parts := strings.Split(cleanPath, "/")

	// Last part is entry name, rest are groups
	if len(parts) <= 1 {
		return []string{}, parts[0]
	}

	return parts[:len(parts)-1], parts[len(parts)-1]
}

// ensureItemsInEnvironments creates missing entries based on items in environments
// Following Single Responsibility Principle - handles entry creation logic
func (m *SecretsBusinessManager) ensureItemsInEnvironments(db *gokeepasslib.Database, headGroup *gokeepasslib.Group, environments map[string][]SecretItem) ([]string, []string, int, error) {
	var entriesCreated []string
	var entriesExisted []string
	var totalFieldsAdded int

	for envName, items := range environments {
		// Find environment group under HEAD
		var envGroup *gokeepasslib.Group
		for i := range headGroup.Groups {
			if headGroup.Groups[i].Name == envName {
				envGroup = &headGroup.Groups[i]
				break
			}
		}

		if envGroup == nil {
			// Environment doesn't exist, skip (should not happen as environments are created first)
			continue
		}

		for _, item := range items {
			// Parse entry path
			pathSegments, entryName := parseEntryPath(item.Entry)

			// Create intermediate groups if needed
			targetGroup := m.dbManager.CreateGroupChain(envGroup, pathSegments)

			// Check if entry already exists in target group
			existingEntries := m.dbManager.FindEntriesByTitle(targetGroup, entryName)

			// CRITICAL SECURITY: Validate entry uniqueness
			if len(existingEntries) > 1 {
				return nil, nil, 0, fmt.Errorf("duplicate entry detected: '%s' found %d times in environment '%s'. Please correct manually in KeePass database", entryName, len(existingEntries), envName)
			}

			if len(existingEntries) == 0 {
				// Entry doesn't exist, create it
				entry := m.dbManager.CreateEntry(targetGroup, entryName)

				// Populate fields for this entry with items that reference it
				fieldsAdded, err := m.PopulateEntryFields(entry, entryName, items)
				if err != nil {
					return nil, nil, 0, fmt.Errorf("failed to populate fields for new entry '%s': %w", entryName, err)
				}
				totalFieldsAdded += fieldsAdded

				// Populate attachments for this entry with items that reference it
				attachmentsAdded, err := m.PopulateEntryAttachments(db, entry, entryName, items)
				if err != nil {
					return nil, nil, 0, fmt.Errorf("failed to populate attachments for new entry '%s': %w", entryName, err)
				}
				totalFieldsAdded += attachmentsAdded // Count attachments as database changes				// Build path for reporting
				fullPath := envName + "/" + item.Entry
				if strings.HasPrefix(item.Entry, "/") {
					fullPath = envName + item.Entry
				}
				entriesCreated = append(entriesCreated, fullPath)
			} else {
				// Entry exists, validate field uniqueness before proceeding
				entry := existingEntries[0]
				if err := ValidateEntryFieldUniqueness(entry, entryName); err != nil {
					return nil, nil, 0, err
				}

				// Populate additional fields for this existing entry
				fieldsAdded, err := m.PopulateEntryFields(entry, entryName, items)
				if err != nil {
					return nil, nil, 0, fmt.Errorf("failed to populate fields for existing entry '%s': %w", entryName, err)
				}
				totalFieldsAdded += fieldsAdded

				// Populate additional attachments for this existing entry
				attachmentsAdded, err := m.PopulateEntryAttachments(db, entry, entryName, items)
				if err != nil {
					return nil, nil, 0, fmt.Errorf("failed to populate attachments for existing entry '%s': %w", entryName, err)
				}
				totalFieldsAdded += attachmentsAdded // Count attachments as database changes				// Entry exists and fields are valid, report it
				fullPath := envName + "/" + item.Entry
				if strings.HasPrefix(item.Entry, "/") {
					fullPath = envName + item.Entry
				}
				entriesExisted = append(entriesExisted, fullPath)
			}
		}
	}

	return entriesCreated, entriesExisted, totalFieldsAdded, nil
}
