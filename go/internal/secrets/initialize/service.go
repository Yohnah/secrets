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
	Setup() error
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
	// Init command now ONLY loads profiles from secrets.yml into an existing database
	// Infrastructure creation (directories, database, keyfile) is handled by 'setup' command

	s.logger.Debug("Starting profile loading process...")

	// Step 1: Determine target directory to find secrets.yml
	var targetDir string
	var err error

	if s.config.ShouldIgnoreGitProject() {
		targetDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
		s.logger.Debug(fmt.Sprintf("Using current directory: %s", targetDir))
	} else {
		targetDir, err = s.findGitRoot()
		if err != nil {
			return fmt.Errorf("not in a git repository. Use --ignore-git-project to work in current directory: %w", err)
		}
		s.logger.Debug(fmt.Sprintf("Found git repository root: %s", targetDir))
	}

	// Step 2: Get database and keyfile paths from configuration
	dbPath := s.config.GetDatabasePath()
	keyfilePath := s.config.GetKeyfilePath()

	// Convert relative paths to absolute paths based on targetDir
	if !filepath.IsAbs(dbPath) {
		dbPath = filepath.Join(targetDir, dbPath)
	}
	if !filepath.IsAbs(keyfilePath) {
		keyfilePath = filepath.Join(targetDir, keyfilePath)
	}

	s.logger.Debug(fmt.Sprintf("Database path: %s", dbPath))
	s.logger.Debug(fmt.Sprintf("Keyfile path: %s", keyfilePath))

	// Step 3: Verify database and keyfile exist
	dbExists := common.FileExists(dbPath)
	keyExists := common.FileExists(keyfilePath)

	if !dbExists || !keyExists {
		return fmt.Errorf("infrastructure not found. Please run 'secrets setup' first to create the database and keyfile.\n\nExpected locations:\n  Database: %s (exists: %v)\n  Keyfile: %s (exists: %v)", dbPath, dbExists, keyfilePath, keyExists)
	}

	// Step 4: Get password and open database
	s.logger.Info("Opening database...")

	// Ensure no previous session is open
	if s.keepass.IsOpen() {
		s.keepass.CloseWithoutSave()
	}

	// Get password (1 time for verification) - secure
	securePassword, err := common.GetPassword(s.config, s.prompt, s.logger, false)
	if err != nil {
		return err
	}
	defer securePassword.Clear() // Ensure password is cleared from memory

	// Try to open database
	if err := s.keepass.Open(dbPath, keyfilePath, securePassword.String()); err != nil {
		return fmt.Errorf("failed to open database: %w\n\nPlease verify your password and keyfile are correct", err)
	}
	defer func() {
		if s.keepass.IsOpen() {
			if err := s.keepass.CloseWithoutSave(); err != nil {
				s.logger.Error(fmt.Sprintf("Failed to close database: %v", err))
			}
		}
	}()

	s.logger.Success("✓ Database opened successfully!")

	// Step 5: Ask for confirmation if not in force mode (safety check)
	if !s.config.IsNoInteractive() {
		confirmed, err := s.prompt.Confirm("Are you sure you want to load profiles from secrets.yml into the database? This may modify your existing database structure.")
		if err != nil {
			return fmt.Errorf("confirmation prompt failed: %w", err)
		}
		if !confirmed {
			s.logger.Info("Operation cancelled by user")
			return nil
		}
	}

	// Step 6: Confirm action if --profile-name is specified (safety check)
	profileName := s.config.GetProfileName()
	if profileName != "" {
		confirmed, err := s.prompt.Confirm(fmt.Sprintf("Are you sure you want to load ONLY the profile '%s' from secrets.yml?", profileName))
		if err != nil {
			return fmt.Errorf("confirmation prompt failed: %w", err)
		}
		if !confirmed {
			s.logger.Info("Operation cancelled by user")
			return nil
		}
	}

	// Step 7: Load profiles from secrets.yml
	if err := s.loadProfilesFromSecretsYML(dbPath, keyfilePath, securePassword.String(), targetDir); err != nil {
		return fmt.Errorf("failed to load profiles from secrets.yml: %w", err)
	}

	s.logger.Success("✓ Profile loading complete!")
	return nil
}

// Setup implements the infrastructure setup logic (without profile loading)
// Creates directory structure, config.yml, keyfile, and empty database
// Does NOT load profiles from secrets.yml (that's what Init does)
func (s *service) Setup() error {
	// Step 1: PULL configuration from ConfigManager
	cfg, err := s.config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Step 2: DECISION - Check NoCreateDatabase from processed config
	noCreateDatabase := cfg.NoCreateDatabase

	s.logger.Debug("Starting setup process (infrastructure only)...")
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

	// Step 4: Determine setup directory using new precedence logic
	secretsDir, isHome, err := s.determineSetupDirectory()
	if err != nil {
		return err
	}

	// Step 4.5: Determine target directory for resolving relative paths (same as Init)
	var targetDir string
	if s.config.ShouldIgnoreGitProject() {
		targetDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
		s.logger.Debug(fmt.Sprintf("Using current directory for path resolution: %s", targetDir))
	} else {
		targetDir, err = s.findGitRoot()
		if err != nil {
			return fmt.Errorf("not in a git repository. Use --ignore-git-project to work in current directory: %w", err)
		}
		s.logger.Debug(fmt.Sprintf("Found git repository root for path resolution: %s", targetDir))
	}

	// Step 5: Create setup directory
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", secretsDir, err)
	}
	s.logger.Debug(fmt.Sprintf("Created directory: %s", secretsDir))

	// Step 6: Add to .gitignore if NOT in home and NOT ignoring git
	if !isHome && !s.config.ShouldIgnoreGitProject() {
		gitRoot, err := s.findGitRoot()
		if err == nil {
			if err := s.addToGitignore(gitRoot); err != nil {
				s.logger.Error(fmt.Sprintf("Failed to add .secrets_yohnah to .gitignore: %v", err))
				s.logger.Info("Please manually add .secrets_yohnah to your .gitignore file")
			}
		}
	}

	// Step 7: Handle --no-create-database flag
	if noCreateDatabase {
		s.logger.Debug("Skipping database and keyfile creation")

		// Create config.yml with no_create_database: true (only if it doesn't exist)
		configPath := filepath.Join(secretsDir, "config.yml")
		if err := s.config.CreateDefaultConfigWithNoCreate(configPath, true); err != nil {
			return fmt.Errorf("failed to create config file: %w", err)
		}

		s.logger.Success("✓ Setup complete!")
		s.logger.Info(fmt.Sprintf("Created: %s", secretsDir))
		s.logger.Info("Database: not created (no_create_database active)")
		s.logger.Info("Keyfile: not created (no_create_database active)")

		return nil
	}

	// Step 8: Prepare database and keyfile paths using config paths
	configPath := filepath.Join(secretsDir, "config.yml")
	dbPath := s.config.GetDatabasePath()
	keyfilePath := s.config.GetKeyfilePath()

	// Convert relative paths to absolute paths based on secretsDir
	if !filepath.IsAbs(dbPath) {
		dbPath = filepath.Join(secretsDir, filepath.Base(dbPath))
	}
	if !filepath.IsAbs(keyfilePath) {
		keyfilePath = filepath.Join(secretsDir, filepath.Base(keyfilePath))
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

	// Step 11: Handle existing database and keyfile
	if dbExists && keyExists {
		s.logger.Info("Database and keyfile already exist.")
		s.logger.Success("✓ Setup already completed!")
		s.logger.Info(fmt.Sprintf("Database: %s", dbPath))
		s.logger.Info(fmt.Sprintf("Keyfile: %s", keyfilePath))

		// NOTE: Setup does NOT verify database access or load profiles
		// Setup only ensures the infrastructure exists
		// Use 'init' command if you need to verify access or load profiles

		return nil
	}

	// Step 12: Ask user if they want to create the database (only if not in no-interactive mode)
	if !cfg.NoInteractive {
		confirmed, err := s.prompt.ConfirmWithDefault("Do you want to create the database?", true)
		if err != nil {
			return fmt.Errorf("failed to get confirmation: %w", err)
		}
		if !confirmed {
			// User declined database creation - create config.yml with no_create_database: true
			s.logger.Debug("User declined database creation")

			// Create config.yml with no_create_database: true
			if err := s.config.CreateDefaultConfigWithNoCreate(configPath, true); err != nil {
				return fmt.Errorf("failed to create config file: %w", err)
			}

			s.logger.Success("✓ Setup complete!")
			s.logger.Info(fmt.Sprintf("Created: %s", secretsDir))
			s.logger.Info("Database: not created (user declined)")
			s.logger.Info("Keyfile: not created (user declined)")
			s.logger.Info("Note: no_create_database is now active in config.yml")

			return nil
		}
	}

	// Step 13: Create new database and keyfile
	s.logger.Info("Creating new database and keyfile...")

	// Get password (2 times for creation - confirmation) - secure
	securePassword, err := common.GetPassword(s.config, s.prompt, s.logger, true)
	if err != nil {
		return err
	}
	defer securePassword.Clear() // Ensure password is cleared from memory

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

	if err := s.keepass.CreateDatabase(dbPath, keyfilePath, securePassword.String(), rootGroupName); err != nil {
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

	// NOTE: Setup does NOT load profiles from secrets.yml
	// That's the responsibility of the 'init' command

	// Step 14: Show success
	s.logger.Success("✓ Setup complete!")
	s.logger.Info(fmt.Sprintf("Created: %s", secretsDir))
	s.logger.Info(fmt.Sprintf("Database: %s", dbPath))
	s.logger.Info(fmt.Sprintf("Keyfile: %s", keyfilePath))

	return nil
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

// determineSetupDirectory determines where to create the setup directory
// based on flags and existing directories.
//
// Precedence logic:
// 1. If --setup-dir-in-home flag is set -> use Home directory
// 2. If --force-recreate and .secrets_yohnah exists -> delete it and use project
// 3. If .secrets_yohnah exists in project -> use project
// 4. If nothing exists -> ask user (or use project default if -f mode)
//
// NOTE: Home directory existence is NOT checked unless --setup-dir-in-home flag is explicitly set.
// The default behavior is to create in the project directory.
func (s *service) determineSetupDirectory() (string, bool, error) {
	// Step 1: Check --setup-dir-in-home flag
	if s.config.ShouldUseHomeDirectory() {
		homeDir, err := common.GetHomeSecretsDirectory()
		if err != nil {
			return "", false, fmt.Errorf("failed to get home directory: %w", err)
		}
		s.logger.Debug(fmt.Sprintf("Using home directory (--setup-dir-in-home): %s", homeDir))
		return homeDir, true, nil
	}

	// Get project directory (Git root or current directory)
	var projectDir string
	var err error
	if s.config.ShouldIgnoreGitProject() {
		projectDir, err = os.Getwd()
		if err != nil {
			return "", false, fmt.Errorf("failed to get current directory: %w", err)
		}
	} else {
		projectDir, err = s.findGitRoot()
		if err != nil {
			return "", false, fmt.Errorf("not in a git repository. Use --ignore-git-project to create in current directory: %w", err)
		}
	}

	projectSecretsDir := filepath.Join(projectDir, ".secrets_yohnah")

	// Get configuration to check ForceRecreate
	cfg, err := s.config.GetConfig()
	if err != nil {
		return "", false, fmt.Errorf("failed to get configuration: %w", err)
	}

	// Step 2: Handle --force-recreate
	// If --force-recreate is set, it means user wants to create in project
	// regardless of whether home directory exists
	if cfg.ForceRecreate && common.DirectoryExists(projectSecretsDir) {
		s.logger.Info(fmt.Sprintf("Deleting existing directory: %s", projectSecretsDir))
		if err := os.RemoveAll(projectSecretsDir); err != nil {
			return "", false, fmt.Errorf("failed to delete existing directory: %w", err)
		}
		// After deletion, will create in project
	}

	// Step 3: Check if .secrets_yohnah exists in project
	if common.DirectoryExists(projectSecretsDir) {
		s.logger.Debug(fmt.Sprintf("Found existing project directory: %s", projectSecretsDir))
		return projectSecretsDir, false, nil
	}

	// Step 4: Nothing exists - ask user or use project default
	// NOTE: We do NOT check for home directory existence here.
	// Home directory is only used if explicitly requested via --setup-dir-in-home flag.
	// Default behavior is to create in project directory.
	if cfg.NoInteractive {
		// Use project directory by default in non-interactive mode
		s.logger.Debug(fmt.Sprintf("Using project directory (default in -f mode): %s", projectSecretsDir))
		return projectSecretsDir, false, nil
	}

	// Ask user where to create the setup directory
	homeDir, err := common.GetHomeSecretsDirectory()
	if err != nil {
		return "", false, fmt.Errorf("failed to get home directory: %w", err)
	}
	return s.promptForSetupDirectory(projectSecretsDir, homeDir)
}

// promptForSetupDirectory asks the user where to create the setup directory
func (s *service) promptForSetupDirectory(projectDir, homeDir string) (string, bool, error) {
	s.logger.Info("")
	s.logger.Info("Where do you want to create the setup directory?")

	// Determine description based on --ignore-git-project flag
	projectDescription := "Project Git"
	if s.config.ShouldIgnoreGitProject() {
		projectDescription = "Current Directory"
	}

	s.logger.Info(fmt.Sprintf("1) %s (%s) [default]", projectDescription, projectDir))
	s.logger.Info(fmt.Sprintf("2) Home (%s)", homeDir))

	// Use fmt.Scanln to read user input
	s.logger.Info("") // Empty line before prompt
	// NOTE: Using fmt.Scan here is acceptable as it's for user input, not output
	// The prompt message is shown via LoggerManager above
	var choice string
	_, err := fmt.Scanln(&choice)
	if err != nil && err.Error() != "unexpected newline" {
		return "", false, fmt.Errorf("failed to get user input: %w", err)
	}

	// Trim whitespace
	choice = strings.TrimSpace(choice)

	// Default to option 1 if empty
	if choice == "" || choice == "1" {
		s.logger.Debug(fmt.Sprintf("User selected project directory: %s", projectDir))
		return projectDir, false, nil
	}

	if choice == "2" {
		s.logger.Debug(fmt.Sprintf("User selected home directory: %s", homeDir))
		return homeDir, true, nil
	}

	return "", false, fmt.Errorf("invalid choice: %s (expected 1 or 2)", choice)
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
// This function orchestrates the validation and creation steps
func (s *service) loadProfilesFromSecretsYML(dbPath, keyfilePath, password, targetDir string) error {
	// Step 1: Validate secrets.yml and get configuration
	secretsConfig, err := s.validateAndReadSecretsYML()
	if err != nil {
		return err
	}

	// If no config returned, nothing to do (not an error)
	if secretsConfig == nil {
		return nil
	}

	// Step 2: Apply the validated configuration to the database
	return s.applySecretsConfig(secretsConfig, dbPath, keyfilePath, password)
}

// validateAndReadSecretsYML validates secrets.yml and returns the configuration
// Returns (nil, nil) if secrets.yml doesn't exist (not an error)
// Returns (config, nil) if validation succeeds
// Returns (nil, error) if validation fails
func (s *service) validateAndReadSecretsYML() (*validator.SecretsConfig, error) {
	// Get secrets.yml path from config (respects --secrets-file flag)
	secretsYMLPath := s.config.GetSecretsFilePath()

	// Check if secrets.yml path is available
	if secretsYMLPath == "" {
		// No secrets.yml available, not an error - just skip
		s.logger.Debug("secrets.yml not found, skipping profile creation")
		return nil, nil
	}

	s.logger.Debug(fmt.Sprintf("Found secrets.yml at: %s", secretsYMLPath))

	// Validate and read secrets.yml
	s.logger.Debug("Validating secrets.yml...")
	secretsConfig, errs := s.validator.ReadAndValidateSecretsYML(secretsYMLPath)
	if len(errs) > 0 {
		// Return first error
		return nil, fmt.Errorf("validation failed: %w", errs[0])
	}

	// Check if there are profiles to create
	if len(secretsConfig.Profiles) == 0 {
		s.logger.Debug("No profiles found in secrets.yml")
		return nil, nil
	}

	return secretsConfig, nil
}

// applySecretsConfig applies a validated secrets configuration to the KeePass database
// Assumes the configuration has already been validated
func (s *service) applySecretsConfig(secretsConfig *validator.SecretsConfig, dbPath, keyfilePath, password string) error {
	// Get profile name from config (respects --profile-name flag)
	specifiedProfileName := s.config.GetProfileName()

	// Filter profiles if --profile-name is specified
	var profilesToProcess []validator.Profile
	if specifiedProfileName != "" {
		// Find the specific profile
		for _, profile := range secretsConfig.Profiles {
			if profile.Metadata.Profile == specifiedProfileName {
				profilesToProcess = append(profilesToProcess, profile)
				break
			}
		}

		// If profile not found, return error
		if len(profilesToProcess) == 0 {
			return fmt.Errorf("profile '%s' not found in secrets.yml", specifiedProfileName)
		}
	} else {
		// No profile specified, process all profiles
		profilesToProcess = secretsConfig.Profiles
	}

	s.logger.Info(fmt.Sprintf("Loading %d profile(s) from secrets.yml...", len(profilesToProcess)))

	// Open database session ONCE for all operations
	if s.keepass.IsOpen() {
		s.keepass.CloseWithoutSave()
	}
	if err := s.keepass.Open(dbPath, keyfilePath, password); err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() {
		if err := s.keepass.SaveAndClose(); err != nil {
			s.logger.Error(fmt.Sprintf("Failed to save and close database: %v", err))
		}
	}()

	// Create each profile
	profilesCreated := 0
	profilesSkipped := 0
	profilesUpdated := 0
	profilesUnchanged := 0

	for _, profile := range profilesToProcess {
		profileName := profile.Metadata.Profile

		// Check if profile already exists
		exists, err := s.keepass.ProfileExists(profileName)
		if err != nil {
			return fmt.Errorf("failed to check if profile '%s' exists: %w", profileName, err)
		}

		if exists {
			s.logger.Debug(fmt.Sprintf("Profile '%s' already exists, checking for updates...", profileName))

			// Track changes
			totalChanges := 0

			// Apply incremental changes to existing profile
			// Create new environments if they don't exist
			envsCreated, err := s.createEnvironments(profileName, profile)
			if err != nil {
				return fmt.Errorf("failed to update environments for profile '%s': %w", profileName, err)
			}
			totalChanges += envsCreated

			// Create new entries if they don't exist (structure only, no keys/fields yet)
			entriesCreated, err := s.createEntries(profileName, profile)
			if err != nil {
				return fmt.Errorf("failed to update entries for profile '%s': %w", profileName, err)
			}
			totalChanges += entriesCreated

			// Create keys/fields for entries
			keysCreated, err := s.createKeys(profileName, profile)
			if err != nil {
				return fmt.Errorf("failed to update keys for profile '%s': %w", profileName, err)
			}
			totalChanges += keysCreated

			// Determine if profile was actually updated
			if totalChanges > 0 {
				s.logger.Debug(fmt.Sprintf("✓ Profile '%s' updated with new changes", profileName))
				profilesUpdated++
			} else {
				s.logger.Debug(fmt.Sprintf("Profile '%s' has no changes", profileName))
				profilesUnchanged++
			}
		} else {
			// Create new profile
			s.logger.Debug(fmt.Sprintf("Creating profile '%s'...", profileName))

			// Validate unique profile name
			existingProfiles, err := s.keepass.GetRootGroups()
			if err != nil {
				return fmt.Errorf("failed to get existing profiles: %w", err)
			}
			if err := s.validator.ValidateUniqueProfileInRoot(existingProfiles, profileName); err != nil {
				return err
			}

			if err := s.keepass.CreateProfile(profileName); err != nil {
				return fmt.Errorf("failed to create profile '%s': %w", profileName, err)
			}

			// Create environments for this profile
			_, err = s.createEnvironments(profileName, profile)
			if err != nil {
				return fmt.Errorf("failed to create environments for profile '%s': %w", profileName, err)
			}

			// Create entries for this profile (structure only, no keys/fields yet)
			_, err = s.createEntries(profileName, profile)
			if err != nil {
				return fmt.Errorf("failed to create entries for profile '%s': %w", profileName, err)
			}

			// Create keys/fields for entries
			_, err = s.createKeys(profileName, profile)
			if err != nil {
				return fmt.Errorf("failed to create keys for profile '%s': %w", profileName, err)
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
	if profilesUnchanged > 0 {
		s.logger.Info(fmt.Sprintf("✓ %d profile(s) has already been loaded with no changes from secrets.yml", profilesUnchanged))
	}
	if profilesSkipped > 0 {
		s.logger.Info(fmt.Sprintf("%d profile(s) already existed (skipped)", profilesSkipped))
	}

	return nil
}

// createEnvironments creates environment groups under the HEAD group of a profile
// Returns the number of environments created
func (s *service) createEnvironments(profileName string, profile validator.Profile) (int, error) {
	// Check if profile has environments
	if len(profile.Environments) == 0 {
		s.logger.Debug(fmt.Sprintf("Profile '%s' has no environments to create", profileName))
		return 0, nil
	}

	s.logger.Debug(fmt.Sprintf("Creating %d environment(s) for profile '%s'...", len(profile.Environments), profileName))

	// Create each environment
	environmentsCreated := 0
	for envName := range profile.Environments {
		// Create environment group under HEAD
		created, err := s.keepass.CreateGroup(profileName, "HEAD", envName)
		if err != nil {
			return 0, fmt.Errorf("failed to create environment '%s': %w", envName, err)
		}

		if created {
			s.logger.Debug(fmt.Sprintf("  ✓ Environment '%s' created", envName))
			environmentsCreated++
		}
	}

	if environmentsCreated > 0 {
		s.logger.Debug(fmt.Sprintf("  ✓ %d environment(s) created", environmentsCreated))
	}

	return environmentsCreated, nil
}

// createKeys creates keys (fields) for entries in a profile
// Groups items by entry and creates all keys with default value
// Returns the number of keys created
func (s *service) createKeys(profileName string, profile validator.Profile) (int, error) {
	// Check if profile has environments
	if len(profile.Environments) == 0 {
		s.logger.Debug(fmt.Sprintf("Profile '%s' has no environments, skipping key creation", profileName))
		return 0, nil
	}

	s.logger.Debug(fmt.Sprintf("Creating keys for profile '%s'...", profileName))

	// Process each environment
	totalKeysCreated := 0
	totalKeysExisted := 0

	for envName, envData := range profile.Environments {
		s.logger.Debug(fmt.Sprintf("  Processing keys for environment '%s'...", envName))

		// Group items by entry path
		itemsByEntry := make(map[string][]validator.Item)
		for _, item := range envData {
			// Use entry path exactly as specified in secrets.yml (only remove leading slash)
			entryPath := item.Entry

			// Remove leading slash if present
			if len(entryPath) > 0 && entryPath[0] == '/' {
				entryPath = entryPath[1:]
			}

			// NOTE: Do NOT remove any prefix - the path in secrets.yml is the exact structure
			// that should exist under the environment in KeePass

			itemsByEntry[entryPath] = append(itemsByEntry[entryPath], item)
		}

		s.logger.Debug(fmt.Sprintf("    Processing keys for %d entry/entries", len(itemsByEntry)))

		// Create keys for each entry
		for entryPath, items := range itemsByEntry {
			s.logger.Debug(fmt.Sprintf("    - Processing entry '%s' (%d items)...", entryPath, len(items)))

			// Collect unique keys for this entry
			uniqueKeys := make(map[string]bool)
			for _, item := range items {
				uniqueKeys[item.Key] = true
			}

			s.logger.Debug(fmt.Sprintf("      Found %d unique key(s) for this entry", len(uniqueKeys)))

			// Create each key
			keysCreated := 0
			keysExisted := 0

			for keyName := range uniqueKeys {
				// Check if it's an attachment
				if strings.HasPrefix(keyName, "attachments/") {
					// Extract attachment name
					attachmentName := strings.TrimPrefix(keyName, "attachments/")

					// Check if attachment already exists
					exists, err := s.keepass.FieldExists(profileName, envName, entryPath, keyName)
					if err != nil {
						return 0, fmt.Errorf("failed to check if attachment '%s' exists in entry '%s': %w", attachmentName, entryPath, err)
					}

					if exists {
						s.logger.Debug(fmt.Sprintf("        - Attachment '%s' already exists (skipped)", attachmentName))
						keysExisted++
						continue
					}

					s.logger.Debug(fmt.Sprintf("        - Creating attachment '%s'...", attachmentName))

					// Create empty attachment
					if err := s.keepass.CreateAttachment(profileName, envName, entryPath, attachmentName, []byte{}); err != nil {
						return 0, fmt.Errorf("failed to create attachment '%s' in entry '%s': %w", attachmentName, entryPath, err)
					}

					s.logger.Debug(fmt.Sprintf("          ✓ Attachment '%s' created", attachmentName))
					keysCreated++
					continue
				}

				// Check if field already exists
				exists, err := s.keepass.FieldExists(profileName, envName, entryPath, keyName)
				if err != nil {
					return 0, fmt.Errorf("failed to check if field '%s' exists in entry '%s': %w", keyName, entryPath, err)
				}

				if exists {
					s.logger.Debug(fmt.Sprintf("        - Field '%s' already exists (skipped)", keyName))
					keysExisted++
					continue
				}

				// Determine if it's a standard or custom field
				if s.keepass.IsStandardField(keyName) {
					// Create standard field
					s.logger.Debug(fmt.Sprintf("        - Creating standard field '%s'...", keyName))

					// Validate unique field in entry
					fullEntryPath := fmt.Sprintf("%s/HEAD/%s/%s", profileName, envName, entryPath)
					existingFields, err := s.keepass.GetFieldsByEntry(fullEntryPath)
					if err != nil {
						return 0, fmt.Errorf("failed to get existing fields in entry '%s': %w", fullEntryPath, err)
					}
					if err := s.validator.ValidateUniqueFieldsInEntry(existingFields, fullEntryPath); err != nil {
						return 0, err
					}

					if err := s.keepass.SetStandardField(profileName, envName, entryPath, keyName, ""); err != nil {
						return 0, fmt.Errorf("failed to create standard field '%s' in entry '%s': %w", keyName, entryPath, err)
					}
				} else {
					// Create custom field
					s.logger.Debug(fmt.Sprintf("        - Creating custom field '%s'...", keyName))

					// Validate unique field in entry
					fullEntryPath := fmt.Sprintf("%s/HEAD/%s/%s", profileName, envName, entryPath)
					existingFields, err := s.keepass.GetFieldsByEntry(fullEntryPath)
					if err != nil {
						return 0, fmt.Errorf("failed to get existing fields in entry '%s': %w", fullEntryPath, err)
					}
					if err := s.validator.ValidateUniqueFieldsInEntry(existingFields, fullEntryPath); err != nil {
						return 0, err
					}

					if err := s.keepass.SetCustomField(profileName, envName, entryPath, keyName, ""); err != nil {
						return 0, fmt.Errorf("failed to create custom field '%s' in entry '%s': %w", keyName, entryPath, err)
					}
				}

				s.logger.Debug(fmt.Sprintf("          ✓ Field '%s' created", keyName))
				keysCreated++
			}

			// Summary for this entry
			if keysCreated > 0 {
				s.logger.Debug(fmt.Sprintf("      ✓ %d key(s) created for entry '%s'", keysCreated, entryPath))
			}
			if keysExisted > 0 {
				s.logger.Debug(fmt.Sprintf("      %d key(s) already existed for entry '%s' (skipped)", keysExisted, entryPath))
			}

			totalKeysCreated += keysCreated
			totalKeysExisted += keysExisted

			// VALIDATION: Check for duplicate fields in this entry
			s.logger.Debug(fmt.Sprintf("      Validating no duplicate fields in entry '%s'...", entryPath))

			// Collect all keys that should exist for this entry
			var expectedKeys []string
			for keyName := range uniqueKeys {
				expectedKeys = append(expectedKeys, keyName)
			}

			// Validate using ValidatorMgr
			if err := s.validator.ValidateUniqueFieldsInEntry(expectedKeys, entryPath); err != nil {
				return 0, fmt.Errorf("validation failed for entry '%s' in environment '%s': %w", entryPath, envName, err)
			}
			s.logger.Debug(fmt.Sprintf("      ✓ No duplicate fields in entry '%s'", entryPath))
		}
	}

	// Overall summary
	if totalKeysCreated > 0 {
		s.logger.Debug(fmt.Sprintf("  ✓ Total: %d key(s) created for profile '%s'", totalKeysCreated, profileName))
	}
	if totalKeysExisted > 0 {
		s.logger.Debug(fmt.Sprintf("  Total: %d key(s) already existed for profile '%s' (skipped)", totalKeysExisted, profileName))
	}

	return totalKeysCreated, nil
}

// createEntries creates entries under each environment for a profile
// It extracts unique entry paths from all items in the profile, validates for duplicates,
// and creates only the entry structure (no keys/fields yet)
// createEntries creates entries (structure only, no keys/fields) for a profile
// Returns the number of entries created
func (s *service) createEntries(profileName string, profile validator.Profile) (int, error) {
	// Check if profile has environments
	if len(profile.Environments) == 0 {
		s.logger.Debug(fmt.Sprintf("Profile '%s' has no environments, skipping entry creation", profileName))
		return 0, nil
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
			// Use entry path exactly as specified in secrets.yml (only remove leading slash)
			entryPath := item.Entry

			// Remove leading slash if present
			if len(entryPath) > 0 && entryPath[0] == '/' {
				entryPath = entryPath[1:]
			}

			// NOTE: Do NOT remove any prefix - the path in secrets.yml is the exact structure
			// that should be created under the environment in KeePass

			uniquePaths[entryPath] = true
		}

		s.logger.Debug(fmt.Sprintf("    Found %d unique entry path(s)", len(uniquePaths)))

		// Create each unique entry
		entriesCreated := 0
		entriesExisted := 0

		for entryPath := range uniquePaths {
			// Check if entry already exists
			exists, err := s.keepass.EntryExists(profileName, envName, entryPath)
			if err != nil {
				return 0, fmt.Errorf("failed to check if entry '%s' exists in environment '%s': %w", entryPath, envName, err)
			}

			if exists {
				s.logger.Debug(fmt.Sprintf("    - Entry '%s' already exists (skipped)", entryPath))
				entriesExisted++
				continue
			}

			// Create entry (empty, no custom fields yet)
			s.logger.Debug(fmt.Sprintf("    - Creating entry '%s'...", entryPath))

			// Validate unique entry path
			existingEntries, err := s.keepass.GetEntriesByEnvironment(profileName, envName)
			if err != nil {
				return 0, fmt.Errorf("failed to get existing entries in environment '%s': %w", envName, err)
			}
			if err := s.validator.ValidateUniqueEntryInPath(existingEntries, entryPath, entryPath); err != nil {
				return 0, err
			}

			if err := s.keepass.CreateEntry(profileName, envName, entryPath); err != nil {
				return 0, fmt.Errorf("failed to create entry '%s' in environment '%s': %w", entryPath, envName, err)
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
		allEntryPaths, err := s.keepass.GetEntriesByEnvironment(profileName, envName)
		if err != nil {
			return 0, fmt.Errorf("failed to get entries for validation in environment '%s': %w", envName, err)
		}

		// Validate no duplicates
		if err := s.validator.ValidateNoDuplicateEntries(envName, allEntryPaths); err != nil {
			return 0, fmt.Errorf("validation failed for environment '%s': %w", envName, err)
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

	return totalEntriesCreated, nil
}
