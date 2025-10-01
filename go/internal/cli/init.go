package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// NewInitCommand follows SRP - creates and configures init command only
// DIP - depends on App interface, not concrete implementation
func NewInitCommand(app *CLIApp) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize configuration",
		Long: `Initialize configuration for secrets management.

Uses global flags to specify configuration files:
  -c, --config                 Path to configuration file (env: SECRETS_YOHNAH_CONFIG_PATH)
  -s, --secrets-config-file    Path to secrets.yml file (env: SECRETS_YOHNAH_SFC_PATH)

Examples:
  secrets init                                      # Use default paths
  secrets init -c /custom/config.yml                # Custom config file
  secrets init --secrets-config-file ./my-secrets.yml  # Custom secrets.yml
  secrets init -s /path/to/secrets.yml              # Using shorthand flag`,
		Run: func(cmd *cobra.Command, args []string) {
			runInit(app, cmd, args)
		},
	}
	
	return cmd
}

// runInit follows SRP - handles init command execution only
func runInit(app *CLIApp, cmd *cobra.Command, args []string) {
	// DIP - depend on interfaces, not concrete implementations
	logger := NewLogger(app.IsVerbose())
	gitFinder := NewGitRootFinder(logger)
	configManager := NewConfigManager(logger)
	gitIgnoreManager := NewGitIgnoreManager(logger)
	passwordProvider := NewPasswordProvider(logger)
	keepassManager := NewKeePassManager(logger)
	prompter := NewInteractivePrompter(logger)
	secretsConfigManager := NewSecretsConfigManager(logger)
	
	logger.Debug("Init command started")
	
	forceMode := app.IsForce()
	if forceMode {
		logger.Debug("Force mode enabled - using default values")
	}
	
	// Find git root
	gitRoot, err := gitFinder.FindGitRoot()
	if err != nil {
		logger.Error("Failed to find git repository root: " + err.Error())
		return
	}
	
	logger.Debug("Working in git repository: " + gitRoot)
	
	// Handle secrets.yml file validation using global flags
	var secretsConfigPath string
	if configFile := app.GetSecretsConfigFile(); configFile != "" {
		// User provided a path via flag or environment variable
		secretsConfigPath = configFile
		if !filepath.IsAbs(secretsConfigPath) {
			// Make relative paths absolute relative to current working directory
			if cwd, err := os.Getwd(); err == nil {
				secretsConfigPath = filepath.Join(cwd, secretsConfigPath)
			}
		}
	} else {
		// No flag provided, look for secrets.yml in project root
		var findErr error
		secretsConfigPath, findErr = secretsConfigManager.FindSecretsConfigFile(gitRoot)
		if findErr != nil {
			logger.Error("Failed to find secrets.yml: " + findErr.Error())
			logger.Info("Create a secrets.yml file in your project root or specify the path as an argument")
			return
		}
	}
	
	// Load and validate secrets.yml
	secretsConfig, err := secretsConfigManager.LoadSecretsConfig(secretsConfigPath)
	if err != nil {
		logger.Error("Failed to load or validate secrets.yml: " + err.Error())
		return
	}
	
	logger.Success("Secrets configuration loaded successfully from: " + secretsConfigPath)
	logger.Info("Profile: " + secretsConfig.Metadata.Profile)
	logger.Info("Default environment: " + secretsConfig.Metadata.DefaultEnvironment)
	
	// Ensure .secrets_yohnah is in .gitignore
	if err := gitIgnoreManager.EnsureSecretsIgnored(gitRoot); err != nil {
		logger.Error("Failed to update .gitignore: " + err.Error())
		return
	}
	
	// Create .secrets_yohnah directory
	secretsDir := filepath.Join(gitRoot, ".secrets_yohnah")
	if err := createSecretsDirectory(secretsDir, logger); err != nil {
		logger.Error("Failed to create secrets directory: " + err.Error())
		return
	}
	
	// Create or verify config.yml (use custom path if provided)
	var configPath string
	if customConfig := app.GetConfig(); customConfig != "" {
		// User provided custom config path via flag or environment variable
		configPath = customConfig
		if !filepath.IsAbs(configPath) {
			// Make relative paths absolute relative to current working directory
			if cwd, err := os.Getwd(); err == nil {
				configPath = filepath.Join(cwd, configPath)
			}
		}
	} else {
		// Use default config path
		configPath = filepath.Join(secretsDir, "config.yml")
	}
	
	if err := createOrVerifyConfig(configPath, configManager, logger); err != nil {
		logger.Error("Failed to create/verify config: " + err.Error())
		return
	}
	
	// Load configuration to get database and keyfile paths
	config, err := configManager.LoadConfig(configPath)
	if err != nil {
		logger.Error("Failed to load configuration: " + err.Error())
		return
	}
	
	// Resolve paths relative to .secrets_yohnah directory
	dbPath, keyfilePath := resolveConfigPaths(secretsDir, config)
	
	logger.Debug("Database path: " + dbPath)
	logger.Debug("Keyfile path: " + keyfilePath)
	
	// Validate paths
	if err := keepassManager.ValidatePaths(dbPath, keyfilePath); err != nil {
		logger.Error("Invalid paths: " + err.Error())
		return
	}
	
	// Check if database already exists
	if keepassManager.DatabaseExists(dbPath) {
		logger.Info("KeePass database already exists: " + dbPath)
	} else {
		// Ask if user wants to create the database
		shouldCreate, err := prompter.AskYesNo(
			"KeePass database does not exist. Do you want to create it at "+dbPath+"?",
			"yes",
			forceMode,
		)
		if err != nil {
			logger.Error("Failed to get user input: " + err.Error())
			return
		}
		
		if shouldCreate {
			if err := createKeePassDatabase(dbPath, keyfilePath, keepassManager, passwordProvider, logger); err != nil {
				logger.Error("Failed to create KeePass database: " + err.Error())
				return
			}
		} else {
			logger.Info("Skipping database creation")
		}
	}
	
	logger.Info("Initialization completed successfully")
	logger.Info("Configuration directory: " + secretsDir)
	logger.Info("Configuration file: " + configPath)
	if keepassManager.DatabaseExists(dbPath) {
		logger.Info("KeePass database: " + dbPath)
		logger.Info("Keyfile: " + keyfilePath)
	}
	logger.Info("Security: .secrets_yohnah is properly excluded from git")
}

// createSecretsDirectory creates the .secrets_yohnah directory if it doesn't exist
func createSecretsDirectory(secretsDir string, logger Logger) error {
	logger.Debug("Checking secrets directory: " + secretsDir)
	
	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		logger.Debug("Creating secrets directory")
		if err := os.MkdirAll(secretsDir, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %v", err)
		}
		logger.Success("Created secrets directory: " + secretsDir)
	} else {
		logger.Debug("Secrets directory already exists")
	}
	
	return nil
}

// createOrVerifyConfig creates config.yml with default values if it doesn't exist
func createOrVerifyConfig(configPath string, configManager ConfigManager, logger Logger) error {
	logger.Debug("Checking config file: " + configPath)
	
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logger.Debug("Creating default config file")
		
		// Create default config
		defaultConfig := configManager.GetDefaultConfig()
		if err := configManager.SaveConfig(configPath, defaultConfig); err != nil {
			return fmt.Errorf("failed to save config: %v", err)
		}
		
		logger.Success("Created config file with default values: " + configPath)
	} else {
		logger.Debug("Config file already exists, verifying...")
		
		// Try to load existing config to verify it's valid
		_, err := configManager.LoadConfig(configPath)
		if err != nil {
			return fmt.Errorf("existing config file is invalid: %v", err)
		}
		
		logger.Debug("Config file is valid")
	}
	
	return nil
}

// resolveConfigPaths resolves relative paths in config to absolute paths
func resolveConfigPaths(secretsDir string, config *Config) (string, string) {
	dbPath := config.DatabasePath
	keyfilePath := config.KeyfilePath
	
	// If paths are relative, make them relative to secrets directory
	if !filepath.IsAbs(dbPath) {
		dbPath = filepath.Join(secretsDir, dbPath)
	}
	
	if !filepath.IsAbs(keyfilePath) {
		keyfilePath = filepath.Join(secretsDir, keyfilePath)
	}
	
	return dbPath, keyfilePath
}

// createKeePassDatabase creates a new KeePass database with keyfile and password
func createKeePassDatabase(dbPath, keyfilePath string, keepassManager KeePassManager, passwordProvider PasswordProvider, logger Logger) error {
	logger.Debug("Starting KeePass database creation process")
	
	// Generate keyfile if it doesn't exist
	if !keepassManager.KeyfileExists(keyfilePath) {
		logger.Debug("Generating keyfile...")
		if err := keepassManager.GenerateKeyfile(keyfilePath); err != nil {
			return fmt.Errorf("failed to generate keyfile: %v", err)
		}
	} else {
		logger.Info("Keyfile already exists: " + keyfilePath)
	}
	
	// Get password from user or environment variable
	password, err := passwordProvider.GetPassword("Enter password for KeePass database: ")
	if err != nil {
		return fmt.Errorf("failed to get password: %v", err)
	}
	
	// Create the database
	if err := keepassManager.CreateDatabase(dbPath, keyfilePath, password); err != nil {
		return fmt.Errorf("failed to create database: %v", err)
	}
	
	logger.Success("KeePass database created successfully")
	return nil
}