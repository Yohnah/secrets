package secrets

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/prompt"
)

// Manager defines the interface for secrets business logic
// InitOptions holds options for the Init command
type InitOptions struct {
	ForceRecreate    bool
	NoCreateDatabase bool
}

type Manager interface {
	Init() error
	InitWithRecreate(forceRecreate bool) error
	InitWithOptions(opts InitOptions) error
}

type manager struct {
	config  config.Manager
	logger  logger.Manager
	prompt  prompt.Manager
	keepass keepass.Manager
}

// NewManager creates a new SecretsManager instance
func NewManager(cfg config.Manager, log logger.Manager, prm prompt.Manager) Manager {
	return &manager{
		config:  cfg,
		logger:  log,
		prompt:  prm,
		keepass: keepass.NewManager(),
	}
}

// Init implements the initialization command logic (compatibility wrapper)
func (m *manager) Init() error {
	return m.InitWithOptions(InitOptions{ForceRecreate: false, NoCreateDatabase: false})
}

// InitWithRecreate implements the initialization logic with force recreate (compatibility wrapper)
func (m *manager) InitWithRecreate(forceRecreate bool) error {
	return m.InitWithOptions(InitOptions{ForceRecreate: forceRecreate, NoCreateDatabase: false})
}

// InitWithOptions implements the full initialization logic with options
func (m *manager) InitWithOptions(opts InitOptions) error {
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
	if err := m.keepass.CreateDatabase(dbPath, keyfilePath, password); err != nil {
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

	// Step 13: Show success
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
