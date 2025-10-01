package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/git"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/prompt"
)

// InitCommand encapsulates the init command functionality
// Follows SRP - Single Responsibility Principle: only handles init command
type InitCommand struct {
	logger          logger.Logger
	configManager   config.Manager
	gitFinder       git.RootFinder
	keepassManager  keepass.Manager
	prompter        prompt.InteractivePrompter
	globalFlags     *GlobalFlags
}

// NewInitCommand creates the init command
// Follows SRP - Single Responsibility Principle: only handles init command creation
func NewInitCommand(
	logger logger.Logger,
	configManager config.Manager,
	gitFinder git.RootFinder,
	keepassManager keepass.Manager,
	prompter prompt.InteractivePrompter,
	globalFlags *GlobalFlags,
) *cobra.Command {
	initCmd := &InitCommand{
		logger:          logger,
		configManager:   configManager,
		gitFinder:       gitFinder,
		keepassManager:  keepassManager,
		prompter:        prompter,
		globalFlags:     globalFlags,
	}

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new secrets project",
		Long: `Initialize a new secrets project with KeePass database and configuration.

This command will:
1. Create the necessary directory structure (.secrets_yohnah)
2. Generate configuration files (config.yml)
3. Create KeePass database with keyfile
4. Respect flag and environment variable precedence

Examples:
  secrets init                              # Initialize in git repository
  secrets init --ignore-git-repository      # Initialize in current directory
  secrets init --verbose                    # Initialize with verbose output
  secrets init --config myconf              # Initialize with custom config path`,
		RunE: initCmd.runInit,
	}

	return cmd
}

// runInit handles the init command execution
// Follows SRP - Single Responsibility Principle: only handles init execution
func (ic *InitCommand) runInit(cmd *cobra.Command, args []string) error {
	ic.logger.Debug("Init command started")
	
	// Determine working directory
	var workingDir string
	ignoreGit, _ := cmd.Flags().GetBool("ignore-git-repository")
	
	if ignoreGit {
		ic.logger.Debug("Ignoring git repository requirement")
		currentDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("Failed to get current directory: %v", err)
		}
		workingDir = currentDir
		ic.logger.Info("Using current directory: " + workingDir)
	} else {
		// Find git root directory
		gitRoot, err := ic.gitFinder.FindGitRoot()
		if err != nil {
			return fmt.Errorf("Failed to find git repository root: %v", err)
		}
		workingDir = gitRoot
		ic.logger.Info("Git root found: " + workingDir)
	}

	// Create .secrets_yohnah directory
	secretsDir := filepath.Join(workingDir, ".secrets_yohnah")
	ic.logger.Debug("Checking if project is already initialized: " + secretsDir)
	
	if ic.isAlreadyInitialized(secretsDir) {
		return fmt.Errorf("Project is already initialized. Secrets directory exists: %s", secretsDir)
	}

	// Ask for confirmation unless force flag is used
	if !ic.globalFlags.Force {
		confirmed, err := ic.prompter.AskYesNo("Initialize secrets project in this directory?", "yes", false)
		if err != nil {
			return fmt.Errorf("Failed to get confirmation: %v", err)
		}
		if !confirmed {
			ic.logger.Print("Operation cancelled by user")
			return nil
		}
	}

	// Create secrets directory
	if err := ic.createSecretsDirectory(secretsDir); err != nil {
		return fmt.Errorf("Failed to create secrets directory: %v", err)
	}

	// Determine config path with precedence: flag > env > default
	var configPath string
	if ic.globalFlags.ConfigPath != "" {
		configPath = ic.globalFlags.ConfigPath
		ic.logger.Info("Using custom config path from flag/env: " + configPath)
	} else {
		configPath = filepath.Join(secretsDir, "config.yml")
		ic.logger.Info("Using default config path: " + configPath)
	}

	// Create or verify config
	if err := ic.createOrVerifyConfig(configPath); err != nil {
		return fmt.Errorf("Failed to create/verify configuration: %v", err)
	}

	// Load config to get database and keyfile paths
	cfg, err := ic.configManager.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("Failed to load config: %v", err)
	}

	// Determine database and keyfile paths with precedence
	dbPath := ic.resolveDatabasePath(cfg, secretsDir)
	keyfilePath := ic.resolveKeyfilePath(cfg, secretsDir)
	password := "123456" // Default password for development

	ic.logger.Info("Database path: " + dbPath)
	ic.logger.Info("Keyfile path: " + keyfilePath)

	// Create KeePass database
	if err := ic.createOrVerifyDatabase(dbPath, keyfilePath, password); err != nil {
		return fmt.Errorf("Failed to create/verify database: %v", err)
	}

	ic.logger.Success("Secrets project initialized successfully")
	ic.logger.Print("Configuration directory: " + secretsDir)
	ic.logger.Print("Config file: " + configPath)
	ic.logger.Print("Database: " + dbPath)
	ic.logger.Print("Keyfile: " + keyfilePath)
	
	return nil
}

// createSecretsDirectory creates the .secrets_yohnah directory
// Follows SRP - Single Responsibility Principle: only handles directory creation
func (ic *InitCommand) createSecretsDirectory(secretsDir string) error {
	ic.logger.Debug("Creating secrets directory: " + secretsDir)

	// Check if directory already exists
	if _, err := os.Stat(secretsDir); err == nil {
		ic.logger.Info("Secrets directory already exists")
		return nil
	}

	// Create directory
	if err := os.MkdirAll(secretsDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	ic.logger.Info("Created secrets directory")
	return nil
}

// createOrVerifyConfig creates or verifies the configuration file
// Follows SRP - Single Responsibility Principle: only handles config creation/verification
func (ic *InitCommand) createOrVerifyConfig(configPath string) error {
	ic.logger.Debug("Creating or verifying config: " + configPath)

	// Check if config already exists
	if _, err := os.Stat(configPath); err == nil {
		ic.logger.Info("Configuration file already exists")
		
		// Try to load and validate existing config
		if _, err := ic.configManager.LoadConfig(configPath); err != nil {
			ic.logger.Warning("Existing config file is invalid: " + err.Error())
			return fmt.Errorf("invalid existing config file")
		}
		
		ic.logger.Info("Existing configuration is valid")
		return nil
	}

	// Create new config
	if err := ic.configManager.CreateDefaultConfig(configPath); err != nil {
		return fmt.Errorf("failed to create config: %v", err)
	}

	ic.logger.Info("Created default configuration file")
	return nil
}

// createOrVerifyDatabase creates or verifies the KeePass database
// Follows SRP - Single Responsibility Principle: only handles database creation/verification
func (ic *InitCommand) createOrVerifyDatabase(dbPath, keyfilePath, password string) error {
	ic.logger.Debug("Creating or verifying database: " + dbPath)

	// Check if database already exists and is valid
	if ic.keepassManager.DatabaseExists(dbPath, keyfilePath, password) {
		ic.logger.Info("KeePass database already exists and is valid")
		return nil
	}

	// Create new database
	if err := ic.keepassManager.CreateDatabase(dbPath, keyfilePath, password); err != nil {
		return fmt.Errorf("failed to create database: %v", err)
	}

	ic.logger.Info("Created KeePass database successfully")
	return nil
}

// resolveDatabasePath resolves database path with precedence: flag > env > config > default
// Follows SRP - Single Responsibility Principle: only handles path resolution
func (ic *InitCommand) resolveDatabasePath(cfg *config.Config, secretsDir string) string {
	// Flag has highest precedence
	if ic.globalFlags.DatabasePath != "" {
		if filepath.IsAbs(ic.globalFlags.DatabasePath) {
			return ic.globalFlags.DatabasePath
		}
		return filepath.Join(secretsDir, ic.globalFlags.DatabasePath)
	}
	
	// Config file has lowest precedence
	if cfg.DatabasePath != "" {
		if filepath.IsAbs(cfg.DatabasePath) {
			return cfg.DatabasePath
		}
		return filepath.Join(secretsDir, cfg.DatabasePath)
	}
	
	// Default fallback
	return filepath.Join(secretsDir, "secrets.kdbx")
}

// resolveKeyfilePath resolves keyfile path with precedence: flag > env > config > default
// Follows SRP - Single Responsibility Principle: only handles path resolution
func (ic *InitCommand) resolveKeyfilePath(cfg *config.Config, secretsDir string) string {
	// Flag has highest precedence
	if ic.globalFlags.KeyfilePath != "" {
		if filepath.IsAbs(ic.globalFlags.KeyfilePath) {
			return ic.globalFlags.KeyfilePath
		}
		return filepath.Join(secretsDir, ic.globalFlags.KeyfilePath)
	}
	
	// Config file has lowest precedence
	if cfg.KeyfilePath != "" {
		if filepath.IsAbs(cfg.KeyfilePath) {
			return cfg.KeyfilePath
		}
		return filepath.Join(secretsDir, cfg.KeyfilePath)
	}
	
	// Default fallback
	return filepath.Join(secretsDir, "secrets.keyfile")
}

// isAlreadyInitialized checks if the secrets project is already initialized
// Follows SRP - Single Responsibility Principle: only handles initialization check
func (ic *InitCommand) isAlreadyInitialized(secretsDir string) bool {
	ic.logger.Debug("Checking if project is already initialized: " + secretsDir)
	
	// Check if .secrets_yohnah directory exists
	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		return false
	}
	
	// Check if config.yml exists
	configPath := filepath.Join(secretsDir, "config.yml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return false
	}
	
	ic.logger.Debug("Project appears to be already initialized")
	return true
}
