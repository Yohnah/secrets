package cli

import (
	"fmt"
	"os"
	"path/filepath"

	configPkg "github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/git"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NewInitCommand creates the init command
// Follows SRP - Single Responsibility Principle: only handles init command creation
func NewInitCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init [secrets-file]",
		Short: "Initialize a new secrets project with KeePass database and configuration",
		Long: `Initialize a new secrets project with KeePass database and configuration.

	This command will:
	1. Read and validate secrets.yml file (from git root or specified path)
	2. Check if current directory is within a git repository (unless --ignore-git-repository)
	3. Create the necessary directory structure (.secrets_yohnah) in git root
	4. Generate configuration files (config.yml)
	5. Create KeePass database with keyfile (unless --no-database is specified)
	6. Create profile structure based on secrets.yml metadata
	7. Add .secrets_yohnah to .gitignore automatically
	8. Respect flag and environment variable precedence

	Examples:
	  secrets init                              # Initialize with secrets.yml from git root
	  secrets init myproject.yml                # Initialize with specific secrets file
	  secrets init /path/to/secrets.yml         # Initialize with absolute path
	  secrets init --no-database                # Initialize configuration only (git required)
	  secrets init --ignore-git-repository      # Initialize in current directory (no git required)
	  secrets init --verbose                    # Initialize with verbose output
	  secrets init --config myconf              # Initialize with custom config path`,
		Args:          cobra.MaximumNArgs(1), // Accept 0 or 1 argument (optional secrets file path)
		SilenceUsage:  true,                  // Don't show usage on execution errors
		SilenceErrors: true,                  // Don't show errors twice
		RunE: func(cmd *cobra.Command, args []string) error {
			// Initialize managers following DDD
			configMgr := configPkg.NewConfigManager()
			dbMgr := keepass.NewDatabaseManager()
			gitMgr := git.NewRepositoryManager()
			secretsMgr := secrets.NewSecretsManager(dbMgr) // Add SecretsManager

			// Determine secrets file path from args
			var secretsFilePath string
			if len(args) > 0 {
				secretsFilePath = args[0]
			}
			// If no path provided, SecretsManager will search in git root

			// ConfigManager is the SINGLE SOURCE OF TRUTH for all configuration
			// Get configuration values respecting precedence: FLAGS > CONFIG.YML > ENV VARS > DEFAULTS

			// Get force flag - try command first, then parent
			force := false
			if cmd.Flags().Lookup("force") != nil {
				force, _ = cmd.Flags().GetBool("force")
			} else if cmd.Parent() != nil && cmd.Parent().Flags().Lookup("force") != nil {
				force, _ = cmd.Parent().Flags().GetBool("force")
			}

			// Get other flags
			verbose, _ := cmd.Flags().GetBool("verbose")
			noCreateDatabase, _ := cmd.Flags().GetBool("no-create-database")
			ignoreGitRepository, _ := cmd.Flags().GetBool("ignore-git-repository")

			// Initialize logger with configuration
			log := logger.NewLogger(verbose)

			// Initialize prompter with configuration
			prompter := prompt.NewInteractivePrompter(force)

			// Git repository validation unless explicitly ignored
			var secretsDir string
			if !ignoreGitRepository {
				if !gitMgr.IsGitRepository() {
					return fmt.Errorf("current directory is not within a git repository. Use --ignore-git-repository to initialize outside a git repository")
				}

				gitRoot, err := gitMgr.FindGitRoot()
				if err != nil {
					return fmt.Errorf("could not find git repository root: %w", err)
				}

				secretsDir = filepath.Join(gitRoot, ".secrets_yohnah")
				log.Debug(fmt.Sprintf("Git repository detected. Using git root: %s", gitRoot))
				log.Debug(fmt.Sprintf("Secrets directory will be: %s", secretsDir))

				// Add .secrets_yohnah to .gitignore if not already present
				if err := gitMgr.EnsureGitIgnore(gitRoot, ".secrets_yohnah"); err != nil {
					log.Debug(fmt.Sprintf("Warning: could not update .gitignore: %v", err))
					// Don't fail the init process for .gitignore issues
				} else {
					log.Debug("Added .secrets_yohnah to .gitignore")
				}
			} else {
				secretsDir = ".secrets_yohnah"
				log.Debug("Git repository validation ignored by user request")
			}

			configPath := filepath.Join(secretsDir, "config.yml")

			// CRITICAL: Validate secrets.yml file before proceeding
			// SecretsManager is the SINGLE SOURCE OF TRUTH for secrets validation
			log.Debug("Validating secrets.yml file...")
			if err := secretsMgr.ProcessSecretsForInit(secretsFilePath); err != nil {
				return err // Return error directly without adding prefix
			}
			log.Info("✓ Secrets.yml file validated successfully")

			// Initial confirmation after git validation and secrets.yml validation
			confirmed, err := prompter.Confirm("Are you sure you want to execute this action?")
			if err != nil {
				return err
			}
			if !confirmed {
				fmt.Fprintln(cmd.OutOrStdout(), "Operation cancelled by user.")
				return nil
			}

			// Check if already initialized
			if _, err := os.Stat(secretsDir); err == nil {
				if _, err := os.Stat(configPath); err == nil {
					fmt.Fprintln(cmd.OutOrStdout(), "✓ Secrets has already been initialized in this directory.")
					return nil
				}
			}

			// Create directory
			if err := os.MkdirAll(secretsDir, 0o700); err != nil {
				return fmt.Errorf("could not create directory %s: %w", secretsDir, err)
			}
			log.Debug(fmt.Sprintf("Created directory: %s", secretsDir))

			// Create config.yml if not exists
			if _, err := os.Stat(configPath); os.IsNotExist(err) {
				configContent := `# SECRETS CONFIGURATION FILE
# This file defines the paths for the KeePass database and keyfile used by the secrets CLI.
# You can change these values to absolute or relative paths as needed.
#
# database_path: Path to the KeePass database file (.kdbx)
# keyfile_path:  Path to the KeePass keyfile (recommended for extra security)

database_path: secrets.kdbx
keyfile_path: secrets.keyfile
`
				if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
					return fmt.Errorf("could not create configuration file: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Project initialized: %s\n", secretsDir)
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Configuration created: %s\n", configPath)
				log.Debug(fmt.Sprintf("Created config file: %s", configPath))
			}

			// Skip database creation if --no-create-database flag is set
			if noCreateDatabase {
				log.Info("Database creation skipped (--no-create-database flag)")
				return nil
			}

			// Load configuration with automatic precedence: flags > config.yml > env > defaults
			// ConfigManager is the SINGLE SOURCE OF TRUTH for all configuration
			externalConfig := viper.GetString("config")
			configForLoad := configPath // Default to local config
			if externalConfig != "" {
				configForLoad = externalConfig // Use external config if specified
			}

			// Only pass flag values if they were explicitly set (not from viper's env fallback)
			var databaseFlag, keyfileFlag string

			// Check for database flag in parent command
			if cmd.Parent() != nil && cmd.Parent().Flags().Changed("database") {
				databaseFlag = viper.GetString("database")
			}

			// Check for keyfile flag in parent command
			if cmd.Parent() != nil && cmd.Parent().Flags().Changed("keyfile") {
				keyfileFlag = viper.GetString("keyfile")
			}

			configOptionsForLoad := configPkg.ConfigOptions{
				DatabaseFlag: databaseFlag,
				KeyfileFlag:  keyfileFlag,
				ConfigPath:   configForLoad,
				BasePath:     secretsDir,
			}
			cfg, err := configMgr.Load(configOptionsForLoad)
			if err != nil {
				log.Debug(fmt.Sprintf("Error loading configuration: %v", err))
				return fmt.Errorf("error loading configuration: %w", err)
			}

			// Use resolved paths from configuration
			dbPath := cfg.DatabasePath
			keyfilePath := cfg.KeyfilePath

			log.Debug(fmt.Sprintf("Resolved database path: %s", dbPath))
			log.Debug(fmt.Sprintf("Resolved keyfile path: %s", keyfilePath))

			// Create parent directories for database and keyfile if they don't exist
			if dbParentDir := filepath.Dir(dbPath); dbParentDir != "." {
				if err := os.MkdirAll(dbParentDir, 0o700); err != nil {
					return fmt.Errorf("could not create parent directory for database %s: %w", dbParentDir, err)
				}
				log.Debug(fmt.Sprintf("Created database parent directory: %s", dbParentDir))
			}
			if keyfileParentDir := filepath.Dir(keyfilePath); keyfileParentDir != "." {
				if err := os.MkdirAll(keyfileParentDir, 0o700); err != nil {
					return fmt.Errorf("could not create parent directory for keyfile %s: %w", keyfileParentDir, err)
				}
				log.Debug(fmt.Sprintf("Created keyfile parent directory: %s", keyfileParentDir))
			}

			// Check if database already exists
			if dbMgr.Exists(dbPath) {
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Database already exists: %s\n", dbPath)
				log.Info(fmt.Sprintf("Database already exists, skipping creation: %s", dbPath))
				return nil
			}

			// Confirm database creation
			dbConfirmed, err := prompter.ConfirmWithDefault("Do you want to create the KeePass database?", true)
			if err != nil {
				return err
			}
			if !dbConfirmed {
				fmt.Fprintln(cmd.OutOrStdout(), "Database creation cancelled. Keyfile will not be created.")
				return nil
			}

			// Get password (interactive or from environment variable)
			password := os.Getenv("SECRETS_YOHNAH_PASSWORD")
			if password == "" {
				password, err = prompter.GetPassword("Enter database password: ")
				if err != nil {
					return fmt.Errorf("failed to get password: %w", err)
				}
				if password == "" {
					return fmt.Errorf("password cannot be empty")
				}
			} else {
				log.Debug("Using password from SECRETS_YOHNAH_PASSWORD environment variable")
			}

			// Create database with keyfile
			log.Info("Creating KeePass database with keyfile...")
			if err := dbMgr.Create(dbPath, keyfilePath, password); err != nil {
				return fmt.Errorf("failed to create database: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✓ Database created: %s\n", dbPath)
			fmt.Fprintf(cmd.OutOrStdout(), "✓ Keyfile created: %s\n", keyfilePath)
			log.Info(fmt.Sprintf("Database created successfully: %s", dbPath))
			log.Info(fmt.Sprintf("Keyfile created successfully: %s", keyfilePath))

			return nil
		},
	}

	// Add command-specific flags
	cmd.Flags().Bool("no-create-database", false, "create only configuration without KeePass database and keyfile")
	cmd.Flags().BoolP("force", "f", false, "force operation without confirmation") // For tests compatibility
	cmd.Flags().BoolP("verbose", "v", false, "verbose output")                     // For tests compatibility
	cmd.Flags().Bool("ignore-git-repository", false, "ignore git repository validation and initialize in current directory")

	return cmd
}
