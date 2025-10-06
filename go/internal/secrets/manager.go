package secrets

import (
	_ "embed"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/output"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/validator"
	"github.com/tobischo/gokeepasslib/v3"
)

//go:embed templates/secrets.tpl.yml
var secretsTemplate string

// Manager defines the interface for secrets business logic
// InitOptions holds options for the Init command
type InitOptions struct {
	ForceRecreate    bool
	NoCreateDatabase bool
	DatabaseName     string
}

type Manager interface {
	Init(opts InitOptions) error
	Status(format string) error
	ShowTemplate(minimal bool) error
}

type manager struct {
	config    config.Manager
	logger    logger.Manager
	prompt    prompt.Manager
	keepass   keepass.Manager
	output    output.Manager
	validator validator.ValidatorManager
}

// NewManager creates a new SecretsManager instance
func NewManager(cfg config.Manager, log logger.Manager, prm prompt.Manager, kp keepass.Manager, out output.Manager, val validator.ValidatorManager) Manager {
	return &manager{
		config:    cfg,
		logger:    log,
		prompt:    prm,
		keepass:   kp,
		output:    out,
		validator: val,
	}
}

// Init implements the full initialization logic with options
func (m *manager) Init(opts InitOptions) error {
	// Step 1: PULL configuration from ConfigManager
	cfg, err := m.config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Step 2: DECISION - Apply precedence for NoCreateDatabase
	// Precedence: FLAG > CONFIG.YML > DEFAULT (false)
	noCreateDatabase := opts.NoCreateDatabase || cfg.NoCreateDatabase

	m.logger.Debug("Starting initialization process...")
	if noCreateDatabase {
		if opts.NoCreateDatabase {
			m.logger.Debug("NoCreateDatabase: true (from --no-create-database flag)")
		} else {
			m.logger.Debug("NoCreateDatabase: true (from config.yml)")
		}
	}

	// Step 3: DECISION - Ask for confirmation if not in force mode
	if !cfg.NoInteractive {
		confirmed, err := m.prompt.Confirm("Are you sure you want to continue?")
		if err != nil {
			return fmt.Errorf("failed to get confirmation: %w", err)
		}
		if !confirmed {
			m.logger.Info("Operation cancelled by user")
			return nil
		}
	}

	// Step 3b: DECISION - Check if no_create_database is active (flag or config)
	if noCreateDatabase {
		m.logger.Debug("Skipping database and keyfile creation")

		// Still need to create .secrets_yohnah directory and config.yml
		var targetDir string
		var err error

		if m.config.ShouldIgnoreGitProject() {
			targetDir, err = os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get current directory: %w", err)
			}
		} else {
			targetDir, err = m.findGitRoot()
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
		if !m.config.ShouldIgnoreGitProject() {
			if err := m.addToGitignore(targetDir); err != nil {
				m.logger.Error(fmt.Sprintf("Failed to add .secrets_yohnah to .gitignore: %v", err))
				m.logger.Info("Please manually add .secrets_yohnah to your .gitignore file")
			}
		}

		// Create config.yml with no_create_database: true (only if it doesn't exist)
		configPath := filepath.Join(secretsDir, "config.yml")
		if err := m.config.CreateDefaultConfigWithNoCreate(configPath, true); err != nil {
			return fmt.Errorf("failed to create config file: %w", err)
		}

		m.logger.Success("✓ Initialization complete!")
		m.logger.Info(fmt.Sprintf("Created: %s", secretsDir))
		m.logger.Info("Database: not created (no_create_database active)")
		m.logger.Info("Keyfile: not created (no_create_database active)")

		return nil
	}

	// Step 4: DECISION - Determine target directory for .secrets_yohnah
	var targetDir string
	if m.config.ShouldIgnoreGitProject() {
		// Use current working directory
		targetDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
		m.logger.Debug(fmt.Sprintf("Using current directory (--ignore-git-project): %s", targetDir))
	} else {
		// Find git root
		targetDir, err = m.findGitRoot()
		if err != nil {
			return fmt.Errorf("not in a git repository. Use --ignore-git-project to create in current directory: %w", err)
		}
		m.logger.Debug(fmt.Sprintf("Found git repository root: %s", targetDir))
	}

	// Step 6: Create .secrets_yohnah directory
	secretsDir := filepath.Join(targetDir, ".secrets_yohnah")
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", secretsDir, err)
	}
	m.logger.Debug(fmt.Sprintf("Created directory: %s", secretsDir))

	// Step 6.1: Add .secrets_yohnah to .gitignore if in a git repository
	if !m.config.ShouldIgnoreGitProject() {
		if err := m.addToGitignore(targetDir); err != nil {
			m.logger.Error(fmt.Sprintf("Failed to add .secrets_yohnah to .gitignore: %v", err))
			m.logger.Info("Please manually add .secrets_yohnah to your .gitignore file")
		}
	}

	// Step 7: Will create config.yml later (after knowing if user wants database or not)
	configPath := filepath.Join(secretsDir, "config.yml")

	// Step 8: Handle --force-recreate flag
	// Convert relative paths to absolute paths based on targetDir
	dbPath := m.config.GetDatabasePath()
	keyfilePath := m.config.GetKeyfilePath()

	// If paths are relative, make them absolute relative to targetDir
	if !filepath.IsAbs(dbPath) {
		dbPath = filepath.Join(targetDir, dbPath)
	}
	if !filepath.IsAbs(keyfilePath) {
		keyfilePath = filepath.Join(targetDir, keyfilePath)
	}

	if opts.ForceRecreate {
		m.logger.Info("Force recreate mode: deleting existing database and keyfile...")

		// Delete database if exists
		if _, err := os.Stat(dbPath); err == nil {
			if err := os.Remove(dbPath); err != nil {
				return fmt.Errorf("failed to remove existing database: %w", err)
			}
			m.logger.Debug(fmt.Sprintf("Deleted existing database: %s", dbPath))
		}

		// Delete keyfile if exists
		if _, err := os.Stat(keyfilePath); err == nil {
			if err := os.Remove(keyfilePath); err != nil {
				return fmt.Errorf("failed to remove existing keyfile: %w", err)
			}
			m.logger.Debug(fmt.Sprintf("Deleted existing keyfile: %s", keyfilePath))
		}
	}

	// Step 9: Verify existence of database and keyfile
	dbExists := fileExists(dbPath)
	keyExists := fileExists(keyfilePath)

	m.logger.Debug(fmt.Sprintf("Database exists: %v at %s", dbExists, dbPath))
	m.logger.Debug(fmt.Sprintf("Keyfile exists: %v at %s", keyExists, keyfilePath))

	// Step 10: Validate consistency (both must exist or both must not exist)
	if dbExists && !keyExists {
		return fmt.Errorf("error: Database exists but keyfile is missing.\nDatabase: %s (exists)\nKeyfile: %s (missing)\n\nPlease either:\n  1. Restore the keyfile\n  2. Remove the database to start fresh\n  3. Specify correct paths with --database and --keyfile", dbPath, keyfilePath)
	}
	if !dbExists && keyExists {
		return fmt.Errorf("error: Keyfile exists but database is missing.\nDatabase: %s (missing)\nKeyfile: %s (exists)\n\nPlease either:\n  1. Restore the database\n  2. Remove the keyfile to start fresh\n  3. Specify correct paths with --database and --keyfile", dbPath, keyfilePath)
	}

	// Step 11: Handle existing database (verify access)
	if dbExists && keyExists {
		m.logger.Info("Database and keyfile already exist. Verifying access...")

		// Get password (1 time for verification)
		password, err := m.getPassword(cfg, false)
		if err != nil {
			return err
		}

		// Try to open database
		_, err = m.keepass.OpenDatabase(dbPath, keyfilePath, password)
		if err != nil {
			return fmt.Errorf("failed to open existing database: %w\n\nPlease verify your password and keyfile are correct", err)
		}

		m.logger.Success("✓ Database access verified!")
		m.logger.Info(fmt.Sprintf("Database: %s", dbPath))
		m.logger.Info(fmt.Sprintf("Keyfile: %s", keyfilePath))

		// Step 11.1: Load profiles from secrets.yml (if exists)
		if err := m.loadProfilesFromSecretsYML(dbPath, keyfilePath, password, targetDir); err != nil {
			// Don't fail if secrets.yml doesn't exist or has issues
			m.logger.Info(fmt.Sprintf("Note: Could not load profiles from secrets.yml: %v", err))
		}

		return nil
	}

	// Step 11b: Ask user if they want to create the database (only if not in no-interactive mode)
	if !cfg.NoInteractive {
		confirmed, err := m.prompt.ConfirmWithDefault("Do you want to create the database?", true)
		if err != nil {
			return fmt.Errorf("failed to get confirmation: %w", err)
		}
		if !confirmed {
			// User declined database creation - create config.yml with no_create_database: true
			m.logger.Debug("User declined database creation")

			// Determine target directory
			var targetDir string
			if m.config.ShouldIgnoreGitProject() {
				targetDir, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			} else {
				targetDir, err = m.findGitRoot()
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
			if err := m.config.CreateDefaultConfigWithNoCreate(configPath, true); err != nil {
				return fmt.Errorf("failed to create config file: %w", err)
			}

			m.logger.Success("✓ Initialization complete!")
			m.logger.Info(fmt.Sprintf("Created: %s", secretsDir))
			m.logger.Info("Database: not created (user declined)")
			m.logger.Info("Keyfile: not created (user declined)")
			m.logger.Info("Note: no_create_database is now active in config.yml")

			return nil
		}
	}

	// Step 12: Create new database and keyfile
	m.logger.Info("Creating new database and keyfile...")

	// Get password (2 times for creation - confirmation)
	password, err := m.getPassword(cfg, true)
	if err != nil {
		return err
	}

	// Generate keyfile
	m.logger.Debug("Generating cryptographically secure keyfile...")
	if err := m.keepass.GenerateKeyfile(keyfilePath); err != nil {
		return fmt.Errorf("failed to generate keyfile: %w", err)
	}
	m.logger.Debug(fmt.Sprintf("Keyfile created: %s", keyfilePath))

	// Create database
	m.logger.Debug("Creating KeePass database in KDBX4 format...")

	// Determine root group name
	rootGroupName := opts.DatabaseName
	if rootGroupName == "" {
		// Use git repo name or default
		rootGroupName = m.getGitRepoName()
	}
	m.logger.Debug(fmt.Sprintf("Using root group name: %s", rootGroupName))

	if err := m.keepass.CreateDatabase(dbPath, keyfilePath, password, rootGroupName); err != nil {
		return fmt.Errorf("failed to create database: %w", err)
	}
	m.logger.Debug(fmt.Sprintf("Database created: %s", dbPath))

	// Create config.yml (only if --ignore-config-file is NOT active)
	if !m.config.ShouldIgnoreConfigFile() {
		if err := m.config.CreateDefaultConfig(configPath); err != nil {
			return fmt.Errorf("failed to create config file: %w", err)
		}
		m.logger.Debug("Created config.yml")
	} else {
		m.logger.Info("Skipping config file creation (--ignore-config-file active)")
	}

	// Step 14: Load profiles from secrets.yml (if exists)
	if err := m.loadProfilesFromSecretsYML(dbPath, keyfilePath, password, targetDir); err != nil {
		// Don't fail the entire init if secrets.yml doesn't exist or has issues
		// Just log a warning
		m.logger.Info(fmt.Sprintf("Note: Could not load profiles from secrets.yml: %v", err))
		m.logger.Info("You can create secrets.yml later and run 'secrets init' again to load profiles")
	}

	// Step 15: Show success
	m.logger.Success("✓ Initialization complete!")
	m.logger.Info(fmt.Sprintf("Created: %s", secretsDir))
	m.logger.Info(fmt.Sprintf("Database: %s", dbPath))
	m.logger.Info(fmt.Sprintf("Keyfile: %s", keyfilePath))

	return nil
}

// getPassword retrieves password from env var or prompts user
// If creating is true, prompts twice for confirmation
func (m *manager) getPassword(cfg *config.Config, creating bool) (string, error) {
	// Check if password is provided via environment variable
	password := os.Getenv("SECRETS_YOHNAH_PASSWORD")

	if password != "" {
		m.logger.Debug("Using password from SECRETS_YOHNAH_PASSWORD environment variable")
		return password, nil
	}

	// If in non-interactive mode and no password provided, fail
	if cfg.NoInteractive {
		return "", fmt.Errorf("password required. Set SECRETS_YOHNAH_PASSWORD environment variable or remove -f flag")
	}

	// Prompt user for password
	if creating {
		// Creating new database: ask twice for confirmation
		return m.prompt.PromptPasswordConfirm("Enter database password")
	}

	// Verifying existing database: ask once
	return m.prompt.PromptPassword("Enter database password: ")
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// makeAbsolutePath converts a relative path to absolute path
func makeAbsolutePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	cwd, _ := os.Getwd()
	return filepath.Join(cwd, path)
}

// getGitRepoName gets the full repository name from git remote origin URL
// Returns "SECRETS YOHNAH" as fallback if not in git repo or parsing fails
func (m *manager) getGitRepoName() string {
	gitRoot, err := m.findGitRoot()
	if err != nil {
		return "SECRETS YOHNAH" // Fallback if not in git repo
	}

	configPath := filepath.Join(gitRoot, ".git", "config")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "SECRETS YOHNAH" // Fallback if cannot read config
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

	return "SECRETS YOHNAH" // Fallback if parsing fails
}

// findGitRoot searches for the git repository root starting from current directory
func (m *manager) findGitRoot() (string, error) {
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
func (m *manager) addToGitignore(gitRoot string) error {
	gitignorePath := filepath.Join(gitRoot, ".gitignore")
	entryToAdd := ".secrets_yohnah"

	// Read existing .gitignore if it exists
	var existingContent []byte
	var err error
	if fileExists(gitignorePath) {
		existingContent, err = os.ReadFile(gitignorePath)
		if err != nil {
			return fmt.Errorf("failed to read .gitignore: %w", err)
		}

		// Check if .secrets_yohnah is already in .gitignore
		lines := strings.Split(string(existingContent), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == entryToAdd {
				m.logger.Debug(".secrets_yohnah already in .gitignore")
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

	m.logger.Debug(fmt.Sprintf("Added .secrets_yohnah to .gitignore"))
	return nil
}

// Status displays the current status of the secrets database
func (m *manager) Status(format string) error {
	m.logger.Debug("Checking database status...")

	// Get configuration
	cfg, err := m.config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Get database and keyfile paths
	dbPath := makeAbsolutePath(m.config.GetDatabasePath())
	keyfilePath := makeAbsolutePath(m.config.GetKeyfilePath())

	// Database name will be read from DB root group (if accessible)
	var databaseName string

	// Check if config.yml exists (unless --ignore-config-file is active)
	var configExists bool
	var configPath string
	if !m.config.ShouldIgnoreConfigFile() {
		configPath = filepath.Join(filepath.Dir(dbPath), "config.yml")
		if _, err := os.Stat(configPath); err == nil {
			configExists = true
		}
	}

	// Check if database exists
	dbInfo, dbErr := os.Stat(dbPath)
	dbExists := dbErr == nil

	// Check if keyfile exists
	keyfileInfo, keyfileErr := os.Stat(keyfilePath)
	keyfileExists := keyfileErr == nil

	// Try to open database to verify accessibility
	var accessible bool
	var accessError string
	var entriesCount int
	var db *gokeepasslib.Database // Keep reference for validation later
	if dbExists && keyfileExists {
		password := cfg.Password
		if password == "" {
			if cfg.NoInteractive {
				accessError = "password required (use SECRETS_YOHNAH_PASSWORD environment variable)"
			} else {
				// Ask for password
				pwd, err := m.prompt.PromptPassword("Enter database password: ")
				if err != nil {
					accessError = fmt.Sprintf("failed to get password: %v", err)
				} else {
					password = pwd
				}
			}
		}

		if password != "" {
			m.logger.Debug("Attempting to open database...")
			openedDB, err := m.keepass.OpenDatabase(dbPath, keyfilePath, password)
			if err != nil {
				accessError = fmt.Sprintf("cannot access database: %v", err)
				accessible = false
			} else {
				accessible = true
				db = openedDB // Save database reference for validation
				m.logger.Debug("Database opened successfully")
				// Read database name from root group (first group in root)
				if len(db.Content.Root.Groups) > 0 {
					databaseName = db.Content.Root.Groups[0].Name
				} else {
					databaseName = "SECRETS YOHNAH" // Fallback if no groups
				}
				// Count entries
				entriesCount = countEntries(db.Content.Root.Groups)
				m.logger.Debug(fmt.Sprintf("Database has %d entries", entriesCount))
			}
		}
	} else {
		accessible = false
		if !dbExists {
			accessError = "database file not found"
		} else if !keyfileExists {
			accessError = "keyfile not found"
		}
	}

	// Build structured status data with display metadata
	statusData := make(map[string]interface{})

	// Top-level display metadata
	statusData["_display"] = map[string]interface{}{
		"type":            "status_report",
		"title":           "Secrets Database Status",
		"title_separator": "=",
		"section_spacing": true,
	}

	// Configuration section (only if not ignored)
	if !m.config.ShouldIgnoreConfigFile() {
		configData := map[string]interface{}{
			"_display": map[string]interface{}{
				"label": "Configuration",
				"fields": []map[string]interface{}{
					{
						"key":    "config_file",
						"label":  "Config file",
						"format": "path_with_status",
					},
				},
			},
			"config_file": configPath,
			"exists":      configExists,
		}
		statusData["configuration"] = configData
	}

	// Database section
	dbData := map[string]interface{}{
		"_display": map[string]interface{}{
			"label": "Database",
			"fields": []map[string]interface{}{
				{"key": "location", "label": "Location", "format": "path_with_status"},
				{"key": "size_human", "label": "Size", "format": "simple", "condition": "exists"},
				{"key": "modified", "label": "Modified", "format": "simple", "condition": "exists"},
				{"key": "accessible", "label": "Accessible", "format": "accessible_status", "condition": "exists"},
				{"key": "database_name", "label": "Database Name", "format": "simple", "condition": "accessible"},
				{"key": "entries_count", "label": "Entries Count", "format": "simple", "condition": "accessible"},
			},
			"not_found_message": "Run 'secrets init' to create the database.",
		},
		"location":      dbPath,
		"exists":        dbExists,
		"database_name": databaseName,
	}
	if dbExists {
		dbData["size_bytes"] = dbInfo.Size()
		dbData["size_human"] = formatFileSize(dbInfo.Size())
		dbData["modified"] = dbInfo.ModTime().Format("2006-01-02 15:04:05")
		dbData["accessible"] = accessible
		dbData["entries_count"] = entriesCount
		dbData["accessible_message"] = "password verified"
		if !accessible {
			dbData["accessible_message"] = accessError
		}
	}
	statusData["database"] = dbData

	// Keyfile section
	keyfileData := map[string]interface{}{
		"_display": map[string]interface{}{
			"label": "Keyfile",
			"fields": []map[string]interface{}{
				{"key": "location", "label": "Location", "format": "path_with_status"},
				{"key": "modified", "label": "Modified", "format": "simple", "condition": "exists"},
			},
			"not_found_message": "Run 'secrets init' to create the keyfile.",
		},
		"location": keyfilePath,
		"exists":   keyfileExists,
	}
	if keyfileExists {
		keyfileData["modified"] = keyfileInfo.ModTime().Format("2006-01-02 15:04:05")
	}
	statusData["keyfile"] = keyfileData

	// VALIDATION SECTION: Check secrets.yml and database compliance
	m.logger.Debug("Running validation checks...")

	var allErrors []error
	validationData := make(map[string]interface{})

	// Validation display metadata
	validationData["_display"] = map[string]interface{}{
		"label": "Validation",
		"fields": []map[string]interface{}{
			{"key": "secrets_file", "label": "Secrets file", "format": "compliance_with_file"},
			{"key": "database_validation", "label": "Database", "format": "compliance_simple"},
		},
		"subsections": []map[string]interface{}{
			{
				"key":             "reports",
				"title":           "Validation Reports",
				"title_separator": "=",
				"format":          "numbered_list",
			},
		},
	}

	// Validate secrets.yml (if available)
	secretsYMLPath := m.config.GetSecretsFilePath()
	secretsYMLData := make(map[string]interface{})

	if secretsYMLPath != "" {
		// Convert to absolute path for consistency with other file paths
		absSecretsYMLPath := makeAbsolutePath(secretsYMLPath)
		m.logger.Debug(fmt.Sprintf("Validating secrets.yml: %s", absSecretsYMLPath))
		secretsYMLData["file"] = absSecretsYMLPath
		secretsYMLData["checked"] = true

		_, validationErrors := m.validator.ReadAndValidateSecretsYML(secretsYMLPath)
		if len(validationErrors) == 0 {
			secretsYMLData["status"] = "Compliance"
			secretsYMLData["symbol"] = "✓"
			m.logger.Debug("secrets.yml validation: Compliance")
		} else {
			secretsYMLData["status"] = "Not compliance"
			secretsYMLData["symbol"] = "✗"
			m.logger.Debug(fmt.Sprintf("secrets.yml validation: Not compliance (%d errors)", len(validationErrors)))
			allErrors = append(allErrors, addPrefixToErrors(validationErrors, "[Secrets file]")...)
		}
	} else {
		secretsYMLData["checked"] = false
		secretsYMLData["status"] = "Not checked (file not found)"
		m.logger.Debug("secrets.yml validation: Skipped (file not found)")
	}
	validationData["secrets_file"] = secretsYMLData

	// Validate database duplicates (if accessible)
	dbValidationData := make(map[string]interface{})

	if accessible && db != nil {
		m.logger.Debug("Validating database for duplicates...")
		dbValidationData["checked"] = true

		// Create adapter to pass database to validator
		dbAdapter := keepass.NewDatabaseAdapter(db)
		duplicateErrors := m.validator.ValidateKeePassDuplicates(dbAdapter)

		if len(duplicateErrors) == 0 {
			dbValidationData["status"] = "Compliance"
			dbValidationData["symbol"] = "✓"
			m.logger.Debug("Database validation: Compliance")
		} else {
			dbValidationData["status"] = "Not compliance"
			dbValidationData["symbol"] = "✗"
			m.logger.Debug(fmt.Sprintf("Database validation: Not compliance (%d errors)", len(duplicateErrors)))
			allErrors = append(allErrors, addPrefixToErrors(duplicateErrors, "[Database]")...)
		}
	} else {
		dbValidationData["checked"] = false
		dbValidationData["status"] = "Not checked (database not accessible)"
		if !accessible {
			m.logger.Debug("Database validation: Skipped (database not accessible)")
		}
	}
	validationData["database_validation"] = dbValidationData

	// Add reports section only if there are errors
	if len(allErrors) > 0 {
		reports := []string{}
		for _, err := range allErrors {
			reports = append(reports, err.Error())
		}
		validationData["reports"] = reports
		m.logger.Debug(fmt.Sprintf("Validation reports: %d total errors", len(allErrors)))
	}

	statusData["validation"] = validationData

	// Pass structured data + format to OutputManager
	if err := m.output.Output(statusData, format); err != nil {
		return fmt.Errorf("failed to output status: %w", err)
	}

	// Return error if database is not accessible
	if !accessible && dbExists {
		return fmt.Errorf("database is not accessible: %s", accessError)
	}

	return nil
}

// addPrefixToErrors adds a prefix to a list of errors
func addPrefixToErrors(errors []error, prefix string) []error {
	prefixed := make([]error, len(errors))
	for i, err := range errors {
		prefixed[i] = fmt.Errorf("%s %w", prefix, err)
	}
	return prefixed
}

// formatFileSize formats a file size in bytes to a human-readable string
func formatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// ShowTemplate outputs the embedded secrets.yml template
func (m *manager) ShowTemplate(minimal bool) error {
	var content string
	if minimal {
		content = m.processMinimalTemplate()
	} else {
		content = secretsTemplate
	}
	return m.output.OutputRaw(content)
}

// processMinimalTemplate generates a minimal version of the template
func (m *manager) processMinimalTemplate() string {
	lines := strings.Split(secretsTemplate, "\n")
	var result strings.Builder
	inSkipSection := false

	for _, line := range lines {
		// Skip decorative lines
		if strings.HasPrefix(line, "# ═══════════════════") {
			continue
		}
		if strings.HasPrefix(line, "# SECRETS.YML TEMPLATE") {
			continue
		}
		if strings.Contains(line, "This file defines") {
			continue
		}

		// Detect start of COMPLETE EXAMPLE section
		if strings.Contains(line, "COMPLETE EXAMPLE") {
			inSkipSection = true
			continue
		}

		// Detect start of FIELD REFERENCE section
		if strings.Contains(line, "FIELD REFERENCE") {
			inSkipSection = true
			continue
		}

		// Detect end of skip section (when we find metadata or environments or outputs)
		if strings.HasPrefix(line, "metadata:") ||
			strings.HasPrefix(line, "environments:") ||
			strings.HasPrefix(line, "outputs:") {
			inSkipSection = false
		}

		// Skip lines in sections we're skipping
		if inSkipSection {
			continue
		}

		// Include the line
		result.WriteString(line)
		result.WriteString("\n")
	}

	return result.String()
}

// loadProfilesFromSecretsYML loads profiles from secrets.yml into the KeePass database
func (m *manager) loadProfilesFromSecretsYML(dbPath, keyfilePath, password, targetDir string) error {
	// Get secrets.yml path from config (respects --secrets-file flag)
	secretsYMLPath := m.config.GetSecretsFilePath()

	// Check if secrets.yml path is available
	if secretsYMLPath == "" {
		// No secrets.yml available, not an error - just skip
		m.logger.Debug("secrets.yml not found, skipping profile creation")
		return nil
	}

	m.logger.Debug(fmt.Sprintf("Found secrets.yml at: %s", secretsYMLPath))

	// Validate and read secrets.yml
	m.logger.Debug("Validating secrets.yml...")
	secretsConfig, errs := m.validator.ReadAndValidateSecretsYML(secretsYMLPath)
	if len(errs) > 0 {
		// Return first error
		return fmt.Errorf("validation failed: %w", errs[0])
	}

	// Check if there are profiles to create
	if len(secretsConfig.Profiles) == 0 {
		m.logger.Debug("No profiles found in secrets.yml")
		return nil
	}

	m.logger.Info(fmt.Sprintf("Loading %d profile(s) from secrets.yml...", len(secretsConfig.Profiles)))

	// Create each profile
	profilesCreated := 0
	profilesSkipped := 0

	for _, profile := range secretsConfig.Profiles {
		profileName := profile.Metadata.Profile

		// Check if profile already exists
		exists, err := m.keepass.ProfileExists(dbPath, keyfilePath, password, profileName)
		if err != nil {
			return fmt.Errorf("failed to check if profile '%s' exists: %w", profileName, err)
		}

		if exists {
			m.logger.Debug(fmt.Sprintf("Profile '%s' already exists (skipped)", profileName))
			profilesSkipped++
			continue
		}

		// Create profile
		m.logger.Debug(fmt.Sprintf("Creating profile '%s'...", profileName))
		if err := m.keepass.CreateProfile(dbPath, keyfilePath, password, profileName); err != nil {
			return fmt.Errorf("failed to create profile '%s': %w", profileName, err)
		}

		m.logger.Info(fmt.Sprintf("✓ Profile '%s' created", profileName))
		profilesCreated++
	}

	// Summary
	if profilesCreated > 0 {
		m.logger.Success(fmt.Sprintf("✓ %d profile(s) created successfully", profilesCreated))
	}
	if profilesSkipped > 0 {
		m.logger.Info(fmt.Sprintf("%d profile(s) already existed (skipped)", profilesSkipped))
	}

	return nil
}

// countEntries recursively counts all entries in the given groups
func countEntries(groups []gokeepasslib.Group) int {
	count := 0
	for _, group := range groups {
		count += len(group.Entries)
		count += countEntries(group.Groups)
	}
	return count
}
