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

	// Database initialization (October 4, 2025)
	// InitializeDatabase handles all business logic for database creation/access
	// This includes: existence check, user confirmation, password retrieval, database creation
	// Returns password for subsequent operations (profile structure creation)
	InitializeDatabase(dbPath, keyfilePath string, skipCreation bool) (string, error)

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

	// Snapshot management (October 4, 2025)
	// CreateSnapshot creates a new snapshot from HEAD
	// This includes: password retrieval, validation, version calculation, user confirmation, group cloning
	// Returns SnapshotResult with version and profile information
	CreateSnapshot(dbPath, keyfilePath, profileName string) (*SnapshotResult, error)

	// DeleteSnapshot deletes a specific snapshot version
	// This includes: password retrieval, validation, HEAD protection, user confirmation, group deletion
	// Returns SnapshotDeleteResult with version and deletion status
	DeleteSnapshot(dbPath, keyfilePath, profileName, version string) (*SnapshotDeleteResult, error)

	// ListSnapshots lists all snapshots with detailed information
	// This includes: password retrieval, validation, stats calculation (environments, entries per env)
	// The extended parameter controls whether to include detailed per-environment breakdown
	// Returns SnapshotsListResult with snapshot information (detailed or basic based on extended)
	ListSnapshots(dbPath, keyfilePath, profileName string, extended bool) (*SnapshotsListResult, error)

	// Secrets.yml integration
	ValidateSecretsFile(secretsData *SecretsData) error
	SyncSecretsToDatabase(secretsData *SecretsData) error
}

// SecretsBusinessManager implements SecretsManager
// Following Single Responsibility Principle (SRP) - handles secrets business logic
// Updated October 4, 2025: Added Prompter and OutputFormatter for complete business decision making
type SecretsBusinessManager struct {
	dbManager  keepass.DatabaseManager
	validator  validator.SecretsValidator
	gitManager git.RepositoryManager
	logger     logger.Logger
	prompter   interface{} // For user confirmations - interface{} for now to avoid import cycles
	formatter  interface{} // For output formatting - interface{} for now to avoid import cycles
}

// NewSecretsManager creates a new secrets manager
// Following Dependency Inversion Principle (DIP) - returns interface, depends on abstraction
// Updated October 4, 2025: Receives all manager dependencies via constructor injection
// This allows SecretsManager to make business decisions based on configuration
// while keeping method signatures clean (receiving primitives, not Config object)
// Parameters:
//   - dbManager: KeePass database operations
//   - log: Logger for structured logging
//   - prompter: User interaction for confirmations (can be nil for now)
//   - formatter: Output formatting according to user preference (can be nil for now)
func NewSecretsManager(dbManager keepass.DatabaseManager, log logger.Logger, prompter interface{}, formatter interface{}) SecretsManager {
	return &SecretsBusinessManager{
		dbManager:  dbManager,
		validator:  validator.NewSecretsValidator(),
		gitManager: git.NewRepositoryManager(),
		logger:     log,
		prompter:   prompter,  // User interaction manager
		formatter:  formatter, // Output formatting manager
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

// SnapshotResult represents the result of snapshot operations (October 4, 2025)
type SnapshotResult struct {
	Version     string // e.g., "v4"
	ProfileName string // e.g., "myproject"
	Created     bool   // true if created, false if cancelled
}

// SnapshotDeleteResult represents the result of a snapshot deletion operation
type SnapshotDeleteResult struct {
	Version     string // e.g., "v2"
	ProfileName string // e.g., "myproject"
	Deleted     bool   // true if deleted, false if cancelled
}

// SnapshotInfo represents detailed information about a snapshot
type SnapshotInfo struct {
	Version      string         `json:"version"`        // e.g., "v2"
	Since        string         `json:"since"`          // Date from metadata (e.g., "2025-10-04 12:30:45")
	Environments int            `json:"environments"`   // Number of environments
	EntriesByEnv map[string]int `json:"entries_by_env"` // Entries count per environment
	TotalEntries int            `json:"total_entries"`  // Total entries across all environments
}

// SnapshotsListResult represents the result of listing snapshots
type SnapshotsListResult struct {
	ProfileName string         `json:"profile_name"`
	Snapshots   []SnapshotInfo `json:"snapshots"`
}

// InitializeDatabase handles all business logic for database initialization
// Following SRP - Single Responsibility: manages database creation/access workflow
// This method encapsulates the complete database initialization business logic:
//  1. Check if database exists
//  2. Get password from environment or prompt user
//  3. If database doesn't exist, confirm creation with user
//  4. Create database with keyfile if confirmed
//
// Returns the password for subsequent operations (profile structure creation)
// Following DDD: This is business logic, not infrastructure - SecretsManager decides what to do
func (m *SecretsBusinessManager) InitializeDatabase(dbPath, keyfilePath string, skipCreation bool) (string, error) {
	// Check if database already exists
	var password string
	if m.dbManager.Exists(dbPath) {
		m.logger.Info(fmt.Sprintf("Database already exists, skipping creation: %s", dbPath))

		// Get password for existing database operations
		password = os.Getenv("SECRETS_YOHNAH_PASSWORD")
		if password == "" {
			// Cast prompter to PasswordProvider interface
			if passwordProvider, ok := m.prompter.(interface {
				GetPassword(prompt string) (string, error)
			}); ok {
				var err error
				password, err = passwordProvider.GetPassword("Enter database password: ")
				if err != nil {
					return "", fmt.Errorf("failed to get password: %w", err)
				}
				if password == "" {
					return "", fmt.Errorf("password cannot be empty")
				}
			} else {
				return "", fmt.Errorf("password provider not available")
			}
		} else {
			m.logger.Debug("Using password from SECRETS_YOHNAH_PASSWORD environment variable")
		}

		return password, nil
	}

	// Database doesn't exist - check if we should skip creation
	if skipCreation {
		return "", fmt.Errorf("database does not exist and creation was skipped (--no-create-database flag)")
	}

	// Confirm database creation with user
	if confirmProvider, ok := m.prompter.(interface {
		ConfirmWithDefault(message string, defaultYes bool) (bool, error)
	}); ok {
		dbConfirmed, err := confirmProvider.ConfirmWithDefault("Do you want to create the KeePass database?", true)
		if err != nil {
			return "", err
		}
		if !dbConfirmed {
			return "", fmt.Errorf("database creation cancelled by user")
		}
	} else {
		return "", fmt.Errorf("confirmation provider not available")
	}

	// Get password (interactive or from environment variable)
	password = os.Getenv("SECRETS_YOHNAH_PASSWORD")
	if password == "" {
		// Cast prompter to PasswordProvider interface for confirmation
		if passwordProvider, ok := m.prompter.(interface {
			GetPasswordWithConfirmation(prompt string) (string, error)
		}); ok {
			var err error
			password, err = passwordProvider.GetPasswordWithConfirmation("Enter database password: ")
			if err != nil {
				return "", fmt.Errorf("failed to get password: %w", err)
			}
		} else {
			return "", fmt.Errorf("password provider not available")
		}
	} else {
		m.logger.Debug("Using password from SECRETS_YOHNAH_PASSWORD environment variable")
	}

	// Create database with keyfile
	m.logger.Info("Creating KeePass database with keyfile...")
	if err := m.dbManager.Create(dbPath, keyfilePath, password); err != nil {
		return "", fmt.Errorf("failed to create database: %w", err)
	}

	m.logger.Info(fmt.Sprintf("Database created successfully: %s", dbPath))
	m.logger.Info(fmt.Sprintf("Keyfile created successfully: %s", keyfilePath))

	return password, nil
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

// CreateSnapshot creates a new snapshot from HEAD
// Following SRP - Single Responsibility: manages snapshot creation workflow
// This method encapsulates the complete snapshot creation business logic:
//  1. Get password from environment or prompt user
//  2. Open database and validate profile/HEAD structure
//  3. Calculate next version number
//  4. Confirm snapshot creation with user
//  5. Clone HEAD group to new version
//  6. Save database
//
// Returns SnapshotResult with version and profile information
// Following DDD: This is business logic, not infrastructure - SecretsManager decides what to do
func (m *SecretsBusinessManager) CreateSnapshot(dbPath, keyfilePath, profileName string) (*SnapshotResult, error) {
	// Get password from environment or prompt user
	password := os.Getenv("SECRETS_YOHNAH_PASSWORD")
	if password == "" {
		// Cast prompter to PasswordProvider interface
		if passwordProvider, ok := m.prompter.(interface {
			GetPassword(prompt string) (string, error)
		}); ok {
			var err error
			password, err = passwordProvider.GetPassword("Enter database password: ")
			if err != nil {
				return nil, fmt.Errorf("failed to get password: %w", err)
			}
			if password == "" {
				return nil, fmt.Errorf("password cannot be empty")
			}
		} else {
			return nil, fmt.Errorf("password provider not available")
		}
	} else {
		m.logger.Debug("Using password from SECRETS_YOHNAH_PASSWORD environment variable")
	}

	// Open database
	db, err := m.dbManager.Open(dbPath, keyfilePath, password)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Find "SECRETS YOHNAH" root group
	var rootGroup *gokeepasslib.Group
	for i := range db.Content.Root.Groups {
		if db.Content.Root.Groups[i].Name == "SECRETS YOHNAH" {
			rootGroup = &db.Content.Root.Groups[i]
			break
		}
	}
	if rootGroup == nil {
		return nil, fmt.Errorf("SECRETS YOHNAH root group not found in database")
	}

	// Find profile group under root
	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profileName {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}
	if profileGroup == nil {
		return nil, fmt.Errorf("profile '%s' not found in database", profileName)
	}

	// Find HEAD group under profile
	var headGroup *gokeepasslib.Group
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == "HEAD" {
			headGroup = &profileGroup.Groups[i]
			break
		}
	}
	if headGroup == nil {
		return nil, fmt.Errorf("HEAD not found under profile '%s'", profileName)
	}

	// Calculate next version number by finding existing snapshots
	existingVersions := make([]int, 0)
	for _, group := range profileGroup.Groups {
		if strings.HasPrefix(group.Name, "v") && group.Name != "HEAD" {
			// Try to parse version number
			var versionNum int
			if _, err := fmt.Sscanf(group.Name, "v%d", &versionNum); err == nil {
				existingVersions = append(existingVersions, versionNum)
			}
		}
	}

	// Find maximum version
	nextVersion := 1
	for _, v := range existingVersions {
		if v >= nextVersion {
			nextVersion = v + 1
		}
	}
	versionName := fmt.Sprintf("v%d", nextVersion)

	m.logger.Debug(fmt.Sprintf("Next snapshot version: %s", versionName))

	// Confirm snapshot creation with user
	if confirmProvider, ok := m.prompter.(interface {
		Confirm(message string) (bool, error)
	}); ok {
		confirmed, err := confirmProvider.Confirm(fmt.Sprintf("Create snapshot %s from HEAD?", versionName))
		if err != nil {
			return nil, err
		}
		if !confirmed {
			return &SnapshotResult{
				Version:     versionName,
				ProfileName: profileName,
				Created:     false,
			}, nil
		}
	} else {
		return nil, fmt.Errorf("confirmation provider not available")
	}

	// Clone HEAD group to new snapshot version
	m.logger.Info(fmt.Sprintf("Cloning HEAD to %s...", versionName))
	snapshotGroup, err := m.dbManager.CloneGroup(headGroup, versionName)
	if err != nil {
		return nil, fmt.Errorf("failed to clone HEAD group: %w", err)
	}

	// Add snapshot group to profile (as sibling of HEAD)
	profileGroup.Groups = append(profileGroup.Groups, *snapshotGroup)

	// Update metadata in HEAD: increment version and update date
	m.logger.Debug("Updating HEAD metadata...")
	var metadataEntry *gokeepasslib.Entry
	for i := range headGroup.Entries {
		if headGroup.Entries[i].GetTitle() == "Profile metadata" {
			metadataEntry = &headGroup.Entries[i]
			break
		}
	}

	if metadataEntry != nil {
		// Get current version and increment it
		currentVersionStr := metadataEntry.GetContent("version")
		currentVersion := 1 // Default to 1 if not found or invalid
		if currentVersionStr != "" {
			if parsed, err := fmt.Sscanf(currentVersionStr, "%d", &currentVersion); err == nil && parsed == 1 {
				// Successfully parsed, increment
				currentVersion++
			}
		} else {
			// No version field found, start at 2 (since we're creating first snapshot)
			currentVersion = 2
		}

		// Update version field
		m.dbManager.SetEntryField(metadataEntry, "version", fmt.Sprintf("%d", currentVersion))

		// Update since field with current timestamp
		currentTime := time.Now().Format("2006-01-02 15:04:05")
		m.dbManager.SetEntryField(metadataEntry, "since", currentTime)

		m.logger.Debug(fmt.Sprintf("Updated HEAD metadata: version=%d, since=%s", currentVersion, currentTime))
	} else {
		// If no metadata entry exists, create it
		m.logger.Debug("No metadata entry found in HEAD, creating one...")
		metadataEntry = m.dbManager.CreateEntry(headGroup, "Profile metadata")
		m.dbManager.SetEntryField(metadataEntry, "version", "2") // Start at 2 since we're creating first snapshot
		currentTime := time.Now().Format("2006-01-02 15:04:05")
		m.dbManager.SetEntryField(metadataEntry, "since", currentTime)
	}

	// Save database
	if err := m.dbManager.Save(db, dbPath, keyfilePath, password); err != nil {
		return nil, fmt.Errorf("failed to save database: %w", err)
	}

	m.logger.Info(fmt.Sprintf("Snapshot %s created successfully", versionName))

	return &SnapshotResult{
		Version:     versionName,
		ProfileName: profileName,
		Created:     true,
	}, nil
}

// DeleteSnapshot deletes a specific snapshot version from the database
// Following SRP - Single Responsibility: manages snapshot deletion workflow
// This method encapsulates the complete snapshot deletion business logic:
//  1. Validate version is not HEAD (HEAD cannot be deleted)
//  2. Get password from environment or prompt user
//  3. Open database and validate profile/snapshot structure
//  4. Confirm deletion with user
//  5. Delete snapshot group
//  6. Save database
//
// Returns SnapshotDeleteResult with version and deletion status
// Following DDD: This is business logic, not infrastructure - SecretsManager decides what to do
func (m *SecretsBusinessManager) DeleteSnapshot(dbPath, keyfilePath, profileName, version string) (*SnapshotDeleteResult, error) {
	// Validate version is not HEAD
	if version == "HEAD" {
		return nil, fmt.Errorf("HEAD cannot be deleted")
	}

	// Get password from environment or prompt user
	password := os.Getenv("SECRETS_YOHNAH_PASSWORD")
	if password == "" {
		// Cast prompter to PasswordProvider interface
		if passwordProvider, ok := m.prompter.(interface {
			GetPassword(prompt string) (string, error)
		}); ok {
			var err error
			password, err = passwordProvider.GetPassword("Enter database password: ")
			if err != nil {
				return nil, fmt.Errorf("failed to get password: %w", err)
			}
			if password == "" {
				return nil, fmt.Errorf("password cannot be empty")
			}
		} else {
			return nil, fmt.Errorf("password provider not available")
		}
	} else {
		m.logger.Debug("Using password from SECRETS_YOHNAH_PASSWORD environment variable")
	}

	// Open database
	db, err := m.dbManager.Open(dbPath, keyfilePath, password)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Find "SECRETS YOHNAH" root group
	var rootGroup *gokeepasslib.Group
	for i := range db.Content.Root.Groups {
		if db.Content.Root.Groups[i].Name == "SECRETS YOHNAH" {
			rootGroup = &db.Content.Root.Groups[i]
			break
		}
	}
	if rootGroup == nil {
		return nil, fmt.Errorf("SECRETS YOHNAH root group not found in database")
	}

	// Find profile group under root
	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profileName {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}
	if profileGroup == nil {
		return nil, fmt.Errorf("profile '%s' not found in database", profileName)
	}

	// Verify snapshot group exists under profile
	snapshotExists := false
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == version {
			snapshotExists = true
			break
		}
	}
	if !snapshotExists {
		return nil, fmt.Errorf("snapshot '%s' not found under profile '%s'", version, profileName)
	}

	m.logger.Debug(fmt.Sprintf("Found snapshot %s under profile %s", version, profileName))

	// Confirm deletion with user
	if confirmProvider, ok := m.prompter.(interface {
		Confirm(message string) (bool, error)
	}); ok {
		confirmed, err := confirmProvider.Confirm(fmt.Sprintf("Delete snapshot %s? This action cannot be undone.", version))
		if err != nil {
			return nil, err
		}
		if !confirmed {
			return &SnapshotDeleteResult{
				Version:     version,
				ProfileName: profileName,
				Deleted:     false,
			}, nil
		}
	} else {
		return nil, fmt.Errorf("confirmation provider not available")
	}

	// Delete snapshot group using KeePassManager CRUD operation
	m.logger.Info(fmt.Sprintf("Deleting snapshot %s...", version))
	if err := m.dbManager.DeleteGroup(profileGroup, version); err != nil {
		return nil, fmt.Errorf("failed to delete snapshot group: %w", err)
	}

	// Save database
	if err := m.dbManager.Save(db, dbPath, keyfilePath, password); err != nil {
		return nil, fmt.Errorf("failed to save database: %w", err)
	}

	m.logger.Info(fmt.Sprintf("Snapshot %s deleted successfully", version))

	return &SnapshotDeleteResult{
		Version:     version,
		ProfileName: profileName,
		Deleted:     true,
	}, nil
}

// ListSnapshots lists all snapshots with detailed information and statistics
// Following SRP - Single Responsibility: manages snapshot listing workflow
// This method encapsulates the complete snapshot listing business logic:
//  1. Get password from environment or prompt user
//  2. Open database and validate profile structure
//  3. Find all snapshot groups (excluding HEAD)
//  4. Calculate statistics for each snapshot (environments, entries count)
//  5. Extract metadata (date/time) from Profile metadata entry if available
//
// Returns SnapshotsListResult with snapshot information (detailed or basic based on extended)
// Following DDD: This is business logic, not infrastructure - SecretsManager decides what to collect
// The extended parameter controls whether to include detailed per-environment breakdown
func (m *SecretsBusinessManager) ListSnapshots(dbPath, keyfilePath, profileName string, extended bool) (*SnapshotsListResult, error) {
	// Get password from environment or prompt user
	password := os.Getenv("SECRETS_YOHNAH_PASSWORD")
	if password == "" {
		// Cast prompter to PasswordProvider interface
		if passwordProvider, ok := m.prompter.(interface {
			GetPassword(prompt string) (string, error)
		}); ok {
			var err error
			password, err = passwordProvider.GetPassword("Enter database password: ")
			if err != nil {
				return nil, fmt.Errorf("failed to get password: %w", err)
			}
			if password == "" {
				return nil, fmt.Errorf("password cannot be empty")
			}
		} else {
			return nil, fmt.Errorf("password provider not available")
		}
	} else {
		m.logger.Debug("Using password from SECRETS_YOHNAH_PASSWORD environment variable")
	}

	// Open database
	db, err := m.dbManager.Open(dbPath, keyfilePath, password)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Find "SECRETS YOHNAH" root group
	var rootGroup *gokeepasslib.Group
	for i := range db.Content.Root.Groups {
		if db.Content.Root.Groups[i].Name == "SECRETS YOHNAH" {
			rootGroup = &db.Content.Root.Groups[i]
			break
		}
	}
	if rootGroup == nil {
		return nil, fmt.Errorf("SECRETS YOHNAH root group not found in database")
	}

	// Find profile group under root
	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profileName {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}
	if profileGroup == nil {
		return nil, fmt.Errorf("profile '%s' not found in database", profileName)
	}

	m.logger.Debug(fmt.Sprintf("Found profile %s, analyzing snapshots...", profileName))

	// Collect all snapshots (excluding HEAD)
	var snapshots []SnapshotInfo
	for _, group := range profileGroup.Groups {
		// Skip HEAD - we only want actual snapshots
		if group.Name == "HEAD" {
			continue
		}

		// Only process groups that look like version numbers (v1, v2, v3...)
		if !strings.HasPrefix(group.Name, "v") {
			continue
		}

		m.logger.Debug(fmt.Sprintf("Processing snapshot %s...", group.Name))

		// Calculate statistics for this snapshot
		info := SnapshotInfo{
			Version:      group.Name,
			Since:        "Unknown", // Default if no metadata found
			Environments: len(group.Groups),
		}

		// Try to extract date from Profile metadata entry if it exists
		for _, entry := range group.Entries {
			if entry.GetTitle() == "Profile metadata" {
				sinceValue := entry.GetContent("since")
				if sinceValue != "" {
					info.Since = sinceValue
				}
				break
			}
		}

		// Count entries per environment (include detailed breakdown only if extended is true)
		totalEntries := 0
		if extended {
			info.EntriesByEnv = make(map[string]int)
			for _, envGroup := range group.Groups {
				entryCount := len(envGroup.Entries)
				info.EntriesByEnv[envGroup.Name] = entryCount
				totalEntries += entryCount
			}
		} else {
			// Just count total entries without breakdown
			for _, envGroup := range group.Groups {
				totalEntries += len(envGroup.Entries)
			}
		}
		info.TotalEntries = totalEntries

		snapshots = append(snapshots, info)
	}

	m.logger.Info(fmt.Sprintf("Found %d snapshots for profile %s", len(snapshots), profileName))

	return &SnapshotsListResult{
		ProfileName: profileName,
		Snapshots:   snapshots,
	}, nil
}
