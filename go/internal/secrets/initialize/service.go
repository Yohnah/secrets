package initialize

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets/common"
	"github.com/Yohnah/secrets/internal/validator"
)

// Default database name when git repository name cannot be determined
const defaultDatabaseName = "SECRETS YOHNAH"

// Service defines the interface for initialization operations
type Service interface {
	Init() error
}

type service struct {
	config    config.Manager
	logger    logger.Manager
	prompt    prompt.Manager
	keepass   keepass.Manager
	validator validator.ValidatorManager
}

// NewService creates a new initialization service instance
func NewService(cfg config.Manager, log logger.Manager, prm prompt.Manager, kp keepass.Manager, val validator.ValidatorManager) Service {
	return &service{
		config:    cfg,
		logger:    log,
		prompt:    prm,
		keepass:   kp,
		validator: val,
	}
}

// Init implements the full initialization logic
// Pulls configuration from ConfigManager (which already processed precedence)
func (s *service) Init() error {
	// Step 1: PULL configuration from ConfigManager
	// ConfigManager has already processed: FLAGS > CONFIG.YML > ENV VARS > DEFAULTS
	cfg, err := s.config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Step 2: DECISION - Check NoCreateDatabase from processed config
	noCreateDatabase := cfg.NoCreateDatabase

	s.logger.Debug("Starting initialization process...")
	if noCreateDatabase {
		s.logger.Debug("NoCreateDatabase: true (from processed configuration)")
	}

	// Step 3: DECISION - Ask for confirmation if not in force mode
	if !cfg.NoInteractive {
		confirmed, err := s.prompt.Confirm("Are you sure you want to continue?")
		if err != nil {
			return fmt.Errorf("failed to get confirmation: %w", err)
		}
		if !confirmed {
			s.logger.Info("Operation cancelled by user")
			return nil
		}
	}

	// Step 3b: DECISION - Check if no_create_database is active (flag or config)
	if noCreateDatabase {
		s.logger.Debug("Skipping database and keyfile creation")

		// Still need to create .secrets_yohnah directory and config.yml
		var targetDir string
		var err error

		if s.config.ShouldIgnoreGitProject() {
			targetDir, err = os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get current directory: %w", err)
			}
		} else {
			targetDir, err = s.findGitRoot()
			if err != nil {
				return fmt.Errorf("not in a git repository. Use --ignore-git-project to create in current directory: %w", err)
			}
		}

		// Create .secrets_yohnah directory
		secretsDir := filepath.Join(targetDir, ".secrets_yohnah")
		if err := os.MkdirAll(secretsDir, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", secretsDir, err)
		}

		// Add .secrets_yohnah to .gitignore if in a git repository
		if !s.config.ShouldIgnoreGitProject() {
			if err := s.addToGitignore(targetDir); err != nil {
				s.logger.Error(fmt.Sprintf("Failed to add .secrets_yohnah to .gitignore: %v", err))
				s.logger.Info("Please manually add .secrets_yohnah to your .gitignore file")
			}
		}

		// Create config.yml with no_create_database: true (only if it doesn't exist)
		configPath := filepath.Join(secretsDir, "config.yml")
		if err := s.config.CreateDefaultConfigWithNoCreate(configPath, true); err != nil {
			return fmt.Errorf("failed to create config file: %w", err)
		}

		s.logger.Success("✓ Initialization complete!")
		s.logger.Info(fmt.Sprintf("Created: %s", secretsDir))
		s.logger.Info("Database: not created (no_create_database active)")
		s.logger.Info("Keyfile: not created (no_create_database active)")

		return nil
	}

	// Step 4: DECISION - Determine target directory for .secrets_yohnah
	var targetDir string
	if s.config.ShouldIgnoreGitProject() {
		// Use current working directory
		targetDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
		s.logger.Debug(fmt.Sprintf("Using current directory (--ignore-git-project): %s", targetDir))
	} else {
		// Find git root
		targetDir, err = s.findGitRoot()
		if err != nil {
			return fmt.Errorf("not in a git repository. Use --ignore-git-project to create in current directory: %w", err)
		}
		s.logger.Debug(fmt.Sprintf("Found git repository root: %s", targetDir))
	}

	// Step 6: Create .secrets_yohnah directory
	secretsDir := filepath.Join(targetDir, ".secrets_yohnah")
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", secretsDir, err)
	}
	s.logger.Debug(fmt.Sprintf("Created directory: %s", secretsDir))

	// Step 6.1: Add .secrets_yohnah to .gitignore if in a git repository
	if !s.config.ShouldIgnoreGitProject() {
		if err := s.addToGitignore(targetDir); err != nil {
			s.logger.Error(fmt.Sprintf("Failed to add .secrets_yohnah to .gitignore: %v", err))
			s.logger.Info("Please manually add .secrets_yohnah to your .gitignore file")
		}
	}

	// Step 7: Will create config.yml later (after knowing if user wants database or not)
	configPath := filepath.Join(secretsDir, "config.yml")

	// Step 8: Handle --force-recreate flag
	// Convert relative paths to absolute paths based on targetDir
	dbPath := s.config.GetDatabasePath()
	keyfilePath := s.config.GetKeyfilePath()

	// If paths are relative, make them absolute relative to targetDir
	if !filepath.IsAbs(dbPath) {
		dbPath = filepath.Join(targetDir, dbPath)
	}
	if !filepath.IsAbs(keyfilePath) {
		keyfilePath = filepath.Join(targetDir, keyfilePath)
	}

	if cfg.ForceRecreate {
		s.logger.Info("Force recreate mode: deleting existing database and keyfile...")

		// Delete database if exists
		if _, err := os.Stat(dbPath); err == nil {
			if err := os.Remove(dbPath); err != nil {
				return fmt.Errorf("failed to remove existing database: %w", err)
			}
			s.logger.Debug(fmt.Sprintf("Deleted existing database: %s", dbPath))
		}

		// Delete keyfile if exists
		if _, err := os.Stat(keyfilePath); err == nil {
			if err := os.Remove(keyfilePath); err != nil {
				return fmt.Errorf("failed to remove existing keyfile: %w", err)
			}
			s.logger.Debug(fmt.Sprintf("Deleted existing keyfile: %s", keyfilePath))
		}
	}

	// Step 9: Verify existence of database and keyfile
	dbExists := common.FileExists(dbPath)
	keyExists := common.FileExists(keyfilePath)

	s.logger.Debug(fmt.Sprintf("Database exists: %v at %s", dbExists, dbPath))
	s.logger.Debug(fmt.Sprintf("Keyfile exists: %v at %s", keyExists, keyfilePath))

	// Step 10: Validate consistency (both must exist or both must not exist)
	if dbExists && !keyExists {
		return fmt.Errorf("error: Database exists but keyfile is missing.\nDatabase: %s (exists)\nKeyfile: %s (missing)\n\nPlease either:\n  1. Restore the keyfile\n  2. Remove the database to start fresh\n  3. Specify correct paths with --database and --keyfile", dbPath, keyfilePath)
	}
	if !dbExists && keyExists {
		return fmt.Errorf("error: Keyfile exists but database is missing.\nDatabase: %s (missing)\nKeyfile: %s (exists)\n\nPlease either:\n  1. Restore the database\n  2. Remove the keyfile to start fresh\n  3. Specify correct paths with --database and --keyfile", dbPath, keyfilePath)
	}

	// Step 11: Handle existing database (verify access)
	if dbExists && keyExists {
		s.logger.Info("Database and keyfile already exist. Verifying access...")

		// Get password (1 time for verification)
		password, err := s.getPassword(cfg, false)
		if err != nil {
			return err
		}

		// Try to open database
		_, err = s.keepass.OpenDatabase(dbPath, keyfilePath, password)
		if err != nil {
			return fmt.Errorf("failed to open existing database: %w\n\nPlease verify your password and keyfile are correct", err)
		}

		s.logger.Success("✓ Database access verified!")
		s.logger.Info(fmt.Sprintf("Database: %s", dbPath))
		s.logger.Info(fmt.Sprintf("Keyfile: %s", keyfilePath))

		// Step 11.1: Load profiles from secrets.yml (if exists)
		if err := s.loadProfilesFromSecretsYML(dbPath, keyfilePath, password, targetDir); err != nil {
			// Don't fail if secrets.yml doesn't exist or has issues
			s.logger.Info(fmt.Sprintf("Note: Could not load profiles from secrets.yml: %v", err))
		}

		return nil
	}

	// Step 11b: Ask user if they want to create the database (only if not in no-interactive mode)
	if !cfg.NoInteractive {
		confirmed, err := s.prompt.ConfirmWithDefault("Do you want to create the database?", true)
		if err != nil {
			return fmt.Errorf("failed to get confirmation: %w", err)
		}
		if !confirmed {
			// User declined database creation - create config.yml with no_create_database: true
			s.logger.Debug("User declined database creation")

			// Determine target directory
			var targetDir string
			if s.config.ShouldIgnoreGitProject() {
				targetDir, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			} else {
				targetDir, err = s.findGitRoot()
				if err != nil {
					return fmt.Errorf("not in a git repository. Use --ignore-git-project to create in current directory: %w", err)
				}
			}

			// Create .secrets_yohnah directory
			secretsDir := filepath.Join(targetDir, ".secrets_yohnah")
			if err := os.MkdirAll(secretsDir, 0700); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", secretsDir, err)
			}

			// Create config.yml with no_create_database: true
			configPath := filepath.Join(secretsDir, "config.yml")
			if err := s.config.CreateDefaultConfigWithNoCreate(configPath, true); err != nil {
				return fmt.Errorf("failed to create config file: %w", err)
			}

			s.logger.Success("✓ Initialization complete!")
			s.logger.Info(fmt.Sprintf("Created: %s", secretsDir))
			s.logger.Info("Database: not created (user declined)")
			s.logger.Info("Keyfile: not created (user declined)")
			s.logger.Info("Note: no_create_database is now active in config.yml")

			return nil
		}
	}

	// Step 12: Create new database and keyfile
	s.logger.Info("Creating new database and keyfile...")

	// Get password (2 times for creation - confirmation)
	password, err := s.getPassword(cfg, true)
	if err != nil {
		return err
	}

	// Generate keyfile
	s.logger.Debug("Generating cryptographically secure keyfile...")
	if err := s.keepass.GenerateKeyfile(keyfilePath); err != nil {
		return fmt.Errorf("failed to generate keyfile: %w", err)
	}
	s.logger.Debug(fmt.Sprintf("Keyfile created: %s", keyfilePath))

	// Create database
	s.logger.Debug("Creating KeePass database in KDBX4 format...")

	// Determine root group name
	rootGroupName := cfg.DatabaseName
	if rootGroupName == "" {
		// Use git repo name or default
		rootGroupName = s.getGitRepoName()
	}
	s.logger.Debug(fmt.Sprintf("Using root group name: %s", rootGroupName))

	if err := s.keepass.CreateDatabase(dbPath, keyfilePath, password, rootGroupName); err != nil {
		return fmt.Errorf("failed to create database: %w", err)
	}
	s.logger.Debug(fmt.Sprintf("Database created: %s", dbPath))

	// Create config.yml (only if --ignore-config-file is NOT active)
	if !s.config.ShouldIgnoreConfigFile() {
		if err := s.config.CreateDefaultConfig(configPath); err != nil {
			return fmt.Errorf("failed to create config file: %w", err)
		}
		s.logger.Debug("Created config.yml")
	} else {
		s.logger.Info("Skipping config file creation (--ignore-config-file active)")
	}

	// Step 14: Load profiles from secrets.yml (if exists)
	if err := s.loadProfilesFromSecretsYML(dbPath, keyfilePath, password, targetDir); err != nil {
		// Don't fail the entire init if secrets.yml doesn't exist or has issues
		// Just log a warning
		s.logger.Info(fmt.Sprintf("Note: Could not load profiles from secrets.yml: %v", err))
		s.logger.Info("You can create secrets.yml later and run 'secrets init' again to load profiles")
	}

	// Step 15: Show success
	s.logger.Success("✓ Initialization complete!")
	s.logger.Info(fmt.Sprintf("Created: %s", secretsDir))
	s.logger.Info(fmt.Sprintf("Database: %s", dbPath))
	s.logger.Info(fmt.Sprintf("Keyfile: %s", keyfilePath))

	return nil
}

// getPassword retrieves password from config or prompts user
// If creating is true, prompts twice for confirmation
func (s *service) getPassword(cfg *config.Config, creating bool) (string, error) {
	// Check if password is provided via config (from env var or other sources)
	if cfg.Password != "" {
		s.logger.Debug("Using password from configuration (SECRETS_YOHNAH_PASSWORD environment variable)")
		return cfg.Password, nil
	}

	// If in non-interactive mode and no password provided, fail
	if cfg.NoInteractive {
		return "", fmt.Errorf("password required. Set SECRETS_YOHNAH_PASSWORD environment variable or remove -f flag")
	}

	// Prompt user for password
	if creating {
		// Creating new database: ask twice for confirmation
		return s.prompt.PromptPasswordConfirm("Enter database password")
	}

	// Verifying existing database: ask once
	return s.prompt.PromptPassword("Enter database password: ")
}

// getGitRepoName gets the full repository name from git remote origin URL
// Returns defaultDatabaseName as fallback if not in git repo or parsing fails
func (s *service) getGitRepoName() string {
	gitRoot, err := s.findGitRoot()
	if err != nil {
		return defaultDatabaseName // Fallback if not in git repo
	}

	configPath := filepath.Join(gitRoot, ".git", "config")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return defaultDatabaseName // Fallback if cannot read config
	}

	lines := strings.Split(string(data), "\n")
	inOrigin := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[remote \"origin\"]") {
			inOrigin = true
			continue
		}
		if inOrigin && strings.HasPrefix(line, "url = ") {
			urlStr := strings.TrimPrefix(line, "url = ")
			// Parse URL to extract github.com/owner/repo
			if parsed, err := url.Parse(urlStr); err == nil {
				path := strings.TrimSuffix(parsed.Path, ".git")
				path = strings.TrimPrefix(path, "/")
				if parsed.Host != "" {
					return parsed.Host + "/" + path
				}
			}
			break
		}
		if strings.HasPrefix(line, "[") && inOrigin {
			break // Next section
		}
	}

	return defaultDatabaseName // Fallback if parsing fails
}

// findGitRoot searches for the git repository root starting from current directory
func (s *service) findGitRoot() (string, error) {
	currentDir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// Walk up the directory tree looking for .git
	for {
		gitDir := filepath.Join(currentDir, ".git")
		if _, err := os.Stat(gitDir); err == nil {
			return currentDir, nil
		}

		// Move to parent directory
		parent := filepath.Dir(currentDir)
		if parent == currentDir {
			// Reached root of filesystem
			return "", fmt.Errorf("not a git repository (or any parent up to mount point)")
		}
		currentDir = parent
	}
}

// addToGitignore adds .secrets_yohnah to .gitignore if not already present
func (s *service) addToGitignore(gitRoot string) error {
	gitignorePath := filepath.Join(gitRoot, ".gitignore")
	entryToAdd := ".secrets_yohnah"

	// Read existing .gitignore if it exists
	var existingContent []byte
	var err error
	if common.FileExists(gitignorePath) {
		existingContent, err = os.ReadFile(gitignorePath)
		if err != nil {
			return fmt.Errorf("failed to read .gitignore: %w", err)
		}

		// Check if .secrets_yohnah is already in .gitignore
		lines := strings.Split(string(existingContent), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == entryToAdd {
				s.logger.Debug(".secrets_yohnah already in .gitignore")
				return nil
			}
		}
	}

	// Add .secrets_yohnah to .gitignore
	var newContent string
	if len(existingContent) > 0 {
		// Ensure file ends with newline before adding new entry
		if !strings.HasSuffix(string(existingContent), "\n") {
			newContent = string(existingContent) + "\n" + entryToAdd + "\n"
		} else {
			newContent = string(existingContent) + entryToAdd + "\n"
		}
	} else {
		// Create new .gitignore with comment
		newContent = "# Secrets Manager - Do not commit sensitive data\n" + entryToAdd + "\n"
	}

	// Write updated .gitignore
	if err := os.WriteFile(gitignorePath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write .gitignore: %w", err)
	}

	s.logger.Debug(fmt.Sprintf("Added .secrets_yohnah to .gitignore"))
	return nil
}

// loadProfilesFromSecretsYML loads profiles from secrets.yml into the KeePass database
func (s *service) loadProfilesFromSecretsYML(dbPath, keyfilePath, password, targetDir string) error {
	// Get secrets.yml path from config (respects --secrets-file flag)
	secretsYMLPath := s.config.GetSecretsFilePath()

	// Check if secrets.yml path is available
	if secretsYMLPath == "" {
		// No secrets.yml available, not an error - just skip
		s.logger.Debug("secrets.yml not found, skipping profile creation")
		return nil
	}

	s.logger.Debug(fmt.Sprintf("Found secrets.yml at: %s", secretsYMLPath))

	// Validate and read secrets.yml
	s.logger.Debug("Validating secrets.yml...")
	secretsConfig, errs := s.validator.ReadAndValidateSecretsYML(secretsYMLPath)
	if len(errs) > 0 {
		// Return first error
		return fmt.Errorf("validation failed: %w", errs[0])
	}

	// Check if there are profiles to create
	if len(secretsConfig.Profiles) == 0 {
		s.logger.Debug("No profiles found in secrets.yml")
		return nil
	}

	s.logger.Info(fmt.Sprintf("Loading %d profile(s) from secrets.yml...", len(secretsConfig.Profiles)))

	// Create each profile
	profilesCreated := 0
	profilesSkipped := 0
	profilesUpdated := 0

	for _, profile := range secretsConfig.Profiles {
		profileName := profile.Metadata.Profile

		// Check if profile already exists
		exists, err := s.keepass.ProfileExists(dbPath, keyfilePath, password, profileName)
		if err != nil {
			return fmt.Errorf("failed to check if profile '%s' exists: %w", profileName, err)
		}

		if exists {
			s.logger.Debug(fmt.Sprintf("Profile '%s' already exists, checking for updates...", profileName))

			// Apply incremental changes to existing profile
			// Create new environments if they don't exist
			if err := s.createEnvironments(dbPath, keyfilePath, password, profileName, profile); err != nil {
				return fmt.Errorf("failed to update environments for profile '%s': %w", profileName, err)
			}

			// Create new entries if they don't exist (structure only, no keys/fields yet)
			if err := s.createEntries(dbPath, keyfilePath, password, profileName, profile); err != nil {
				return fmt.Errorf("failed to update entries for profile '%s': %w", profileName, err)
			}

			s.logger.Debug(fmt.Sprintf("✓ Profile '%s' updated with any new changes", profileName))
			profilesUpdated++
		} else {
			// Create new profile
			s.logger.Debug(fmt.Sprintf("Creating profile '%s'...", profileName))
			if err := s.keepass.CreateProfile(dbPath, keyfilePath, password, profileName); err != nil {
				return fmt.Errorf("failed to create profile '%s': %w", profileName, err)
			}

			// Create environments for this profile
			if err := s.createEnvironments(dbPath, keyfilePath, password, profileName, profile); err != nil {
				return fmt.Errorf("failed to create environments for profile '%s': %w", profileName, err)
			}

			// Create entries for this profile (structure only, no keys/fields yet)
			if err := s.createEntries(dbPath, keyfilePath, password, profileName, profile); err != nil {
				return fmt.Errorf("failed to create entries for profile '%s': %w", profileName, err)
			}

			s.logger.Info(fmt.Sprintf("✓ Profile '%s' created", profileName))
			profilesCreated++
		}
	}

	// Summary
	if profilesCreated > 0 {
		s.logger.Success(fmt.Sprintf("✓ %d profile(s) created successfully", profilesCreated))
	}
	if profilesUpdated > 0 {
		s.logger.Info(fmt.Sprintf("✓ %d profile(s) updated with changes from secrets.yml", profilesUpdated))
	}
	if profilesSkipped > 0 {
		s.logger.Info(fmt.Sprintf("%d profile(s) already existed (skipped)", profilesSkipped))
	}

	return nil
}

// createEnvironments creates environment groups under the HEAD group of a profile
func (s *service) createEnvironments(dbPath, keyfilePath, password, profileName string, profile validator.Profile) error {
	// Check if profile has environments
	if len(profile.Environments) == 0 {
		s.logger.Debug(fmt.Sprintf("Profile '%s' has no environments to create", profileName))
		return nil
	}

	s.logger.Debug(fmt.Sprintf("Creating %d environment(s) for profile '%s'...", len(profile.Environments), profileName))

	// Create each environment
	environmentsCreated := 0
	for envName := range profile.Environments {
		// Create environment group under HEAD
		if err := s.keepass.CreateGroup(dbPath, keyfilePath, password, profileName, "HEAD", envName); err != nil {
			return fmt.Errorf("failed to create environment '%s': %w", envName, err)
		}

		s.logger.Debug(fmt.Sprintf("  ✓ Environment '%s' created", envName))
		environmentsCreated++
	}

	if environmentsCreated > 0 {
		s.logger.Debug(fmt.Sprintf("  ✓ %d environment(s) created", environmentsCreated))
	}

	return nil
}

// createEntries creates entries under each environment for a profile
// It extracts unique entry paths from all items in the profile, validates for duplicates,
// and creates only the entry structure (no keys/fields yet)
func (s *service) createEntries(dbPath, keyfilePath, password, profileName string, profile validator.Profile) error {
	// Check if profile has environments
	if len(profile.Environments) == 0 {
		s.logger.Debug(fmt.Sprintf("Profile '%s' has no environments, skipping entry creation", profileName))
		return nil
	}

	s.logger.Debug(fmt.Sprintf("Creating entries for profile '%s'...", profileName))

	// Process each environment
	totalEntriesCreated := 0
	totalEntriesExisted := 0

	for envName, envData := range profile.Environments {
		s.logger.Debug(fmt.Sprintf("  Processing environment '%s'...", envName))

		// Collect unique entry paths from all items in this environment
		uniquePaths := make(map[string]bool)
		for _, item := range envData {
			// The Entry field contains the full path like "dev/app/database" or "prod/app/cache"
			// Remove environment prefix from path (case-insensitive)
			entryPath := item.Entry
			if strings.HasPrefix(strings.ToLower(entryPath), strings.ToLower(envName)+"/") {
				entryPath = strings.TrimPrefix(entryPath, envName+"/")
				// Also try with different case
				if strings.HasPrefix(strings.ToLower(item.Entry), strings.ToLower(envName)+"/") {
					entryPath = item.Entry[len(envName)+1:]
				}
			}

			uniquePaths[entryPath] = true
		}

		s.logger.Debug(fmt.Sprintf("    Found %d unique entry path(s)", len(uniquePaths)))

		// Create each unique entry
		entriesCreated := 0
		entriesExisted := 0

		for entryPath := range uniquePaths {
			// Check if entry already exists
			exists, err := s.keepass.EntryExists(dbPath, keyfilePath, password, profileName, envName, entryPath)
			if err != nil {
				return fmt.Errorf("failed to check if entry '%s' exists in environment '%s': %w", entryPath, envName, err)
			}

			if exists {
				s.logger.Debug(fmt.Sprintf("    - Entry '%s' already exists (skipped)", entryPath))
				entriesExisted++
				continue
			}

			// Create entry (empty, no custom fields yet)
			s.logger.Debug(fmt.Sprintf("    - Creating entry '%s'...", entryPath))
			if err := s.keepass.CreateEntry(dbPath, keyfilePath, password, profileName, envName, entryPath); err != nil {
				return fmt.Errorf("failed to create entry '%s' in environment '%s': %w", entryPath, envName, err)
			}

			s.logger.Debug(fmt.Sprintf("      ✓ Entry '%s' created", entryPath))
			entriesCreated++
		}

		// Summary for this environment
		if entriesCreated > 0 {
			s.logger.Debug(fmt.Sprintf("    ✓ %d entry/entries created in environment '%s'", entriesCreated, envName))
		}
		if entriesExisted > 0 {
			s.logger.Debug(fmt.Sprintf("    %d entry/entries already existed in environment '%s' (skipped)", entriesExisted, envName))
		}

		totalEntriesCreated += entriesCreated
		totalEntriesExisted += entriesExisted

		// VALIDATION: Check for duplicate entries in the database
		s.logger.Debug(fmt.Sprintf("    Validating no duplicate entries in environment '%s'...", envName))

		// Get all entry paths for this environment from the database
		allEntryPaths, err := s.keepass.GetEntriesByEnvironment(dbPath, keyfilePath, password, profileName, envName)
		if err != nil {
			return fmt.Errorf("failed to get entries for validation in environment '%s': %w", envName, err)
		}

		// Validate no duplicates
		if err := s.validator.ValidateNoDuplicateEntries(envName, allEntryPaths); err != nil {
			return fmt.Errorf("validation failed for environment '%s': %w", envName, err)
		}
		s.logger.Debug(fmt.Sprintf("    ✓ No duplicates found in environment '%s'", envName))
	}

	// Overall summary
	if totalEntriesCreated > 0 {
		s.logger.Debug(fmt.Sprintf("  ✓ Total: %d entry/entries created for profile '%s'", totalEntriesCreated, profileName))
	}
	if totalEntriesExisted > 0 {
		s.logger.Debug(fmt.Sprintf("  Total: %d entry/entries already existed for profile '%s' (skipped)", totalEntriesExisted, profileName))
	}

	return nil
}
