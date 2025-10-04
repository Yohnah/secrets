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

			// Determine secrets file path from args
			var secretsFilePath string
			if len(args) > 0 {
				secretsFilePath = args[0]
			}
			// If no path provided, SecretsManager will search in git root

			// Get command-specific flags
			verbose, _ := cmd.Flags().GetBool("verbose")
			force, _ := cmd.Flags().GetBool("force")
			noCreateDatabase, _ := cmd.Flags().GetBool("no-create-database")
			ignoreGitRepository, _ := cmd.Flags().GetBool("ignore-git-repository")

			// Detect global flags if explicitly set
			var databaseFlag, keyfileFlag string
			if cmd.Parent() != nil && cmd.Parent().Flags().Changed("database") {
				databaseFlag = viper.GetString("database")
			}
			if cmd.Parent() != nil && cmd.Parent().Flags().Changed("keyfile") {
				keyfileFlag = viper.GetString("keyfile")
			}

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
			} else {
				secretsDir = ".secrets_yohnah"
			}

			configPath := filepath.Join(secretsDir, "config.yml")

			// Determine final config path
			externalConfig := viper.GetString("config")
			configForLoad := configPath
			if externalConfig != "" {
				configForLoad = externalConfig
			}

			// ConfigManager is the SINGLE SOURCE OF TRUTH for ALL configuration
			// Load configuration with automatic precedence: FLAGS > CONFIG.YML > ENV VARS > DEFAULTS
			cfg, err := configMgr.Load(configPkg.ConfigOptions{
				DatabaseFlag: databaseFlag,
				KeyfileFlag:  keyfileFlag,
				VerboseFlag:  verbose,
				ForceFlag:    force,
				CommandFlags: map[string]interface{}{
					"no-create-database":    noCreateDatabase,
					"ignore-git-repository": ignoreGitRepository,
				},
				ConfigPath: configForLoad,
				BasePath:   secretsDir,
			})
			if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("error loading configuration: %w", err)
			}

			// Initialize logger with configuration from ConfigManager
			log := logger.NewLogger(cfg.Verbose)

			// Initialize prompter with configuration from ConfigManager
			prompter := prompt.NewInteractivePrompter(cfg.Force)

			// TODO: Initialize output formatter when needed
			// outputFormatter := output.NewFormatter(cfg.OutputFormat)

			// Initialize SecretsManager with all dependencies (DIP)
			// SecretsManager receives pre-configured managers to make business decisions
			// Methods still receive primitives (ISP) extracted from Config by CLI
			secretsMgr := secrets.NewSecretsManager(dbMgr, log, prompter, nil)

			// Log git repository status
			if !ignoreGitRepository {
				gitRoot, _ := gitMgr.FindGitRoot()
				log.Debug(fmt.Sprintf("Git repository detected. Using git root: %s", gitRoot))
				log.Debug(fmt.Sprintf("Secrets directory will be: %s", secretsDir))

				// Add .secrets_yohnah to .gitignore if not already present
				if err := gitMgr.EnsureGitIgnore(gitRoot, ".secrets_yohnah"); err != nil {
					log.Debug(fmt.Sprintf("Warning: could not update .gitignore: %v", err))
				} else {
					log.Debug("Added .secrets_yohnah to .gitignore")
				}
			} else {
				log.Debug("Git repository validation ignored by user request")
			}

			// CRITICAL: Validate secrets.yml file before proceeding
			// SecretsManager is the SINGLE SOURCE OF TRUTH for secrets validation
			log.Debug("Validating secrets.yml file...")
			if err := secretsMgr.ProcessSecretsForInit(secretsFilePath); err != nil {
				return err
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
				}
			} else {
				// Create directory if it doesn't exist
				if err := os.MkdirAll(secretsDir, 0o700); err != nil {
					return fmt.Errorf("could not create directory %s: %w", secretsDir, err)
				}
				log.Debug(fmt.Sprintf("Created directory: %s", secretsDir))
			}

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

			// Use resolved paths from configuration (ConfigManager already applied precedence)
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

			// Initialize database through SecretsManager (business logic layer)
			// SecretsManager handles: existence check, user confirmation, password retrieval, database creation
			// Following DDD: SecretsManager is the CORE that takes ALL business decisions
			password, err := secretsMgr.InitializeDatabase(dbPath, keyfilePath, noCreateDatabase)
			if err != nil {
				return err
			}

			// Display success messages to user
			if dbMgr.Exists(dbPath) {
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Database: %s\n", dbPath)
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Keyfile: %s\n", keyfilePath)
			}

			// Create profile structure if secrets.yml is present and valid
			// This always runs whether database was created or already existed
			config, err := secretsMgr.LoadAndValidateSecretsFile(secretsFilePath)
			if err == nil && config.Metadata.Profile != "" {
				log.Info("Creating profile structure in database...")

				// Convert validator types to secrets types
				environments := make(map[string][]secrets.SecretItem)
				for envName, items := range config.Environments {
					secretItems := make([]secrets.SecretItem, len(items))
					for i, item := range items {
						secretItems[i] = secrets.SecretItem{
							Name:  item.Name,
							Entry: item.Entry,
							Key:   item.Key,
							Type:  item.Type,
						}
					}
					environments[envName] = secretItems
				}

				result, err := secretsMgr.EnsureProfileStructure(dbPath, keyfilePath, password, config.Metadata.Profile, environments)
				if err != nil {
					log.Debug(fmt.Sprintf("Warning: failed to create profile structure: %v", err))
					// Don't fail the init process for profile structure issues - just warn
				} else {
					// Determine if any structural changes were made
					structureUpdated := result.ProfileCreated || result.HeadCreated ||
						len(result.EnvironmentsCreated) > 0 || len(result.EntriesCreated) > 0 || result.FieldsAdded > 0

					// Show appropriate message based on what was actually created/found
					if result.ProfileCreated && result.HeadCreated {
						fmt.Fprintf(cmd.OutOrStdout(), "✓ Profile structure created: %s → HEAD\n", result.ProfileName)
						fmt.Fprintf(cmd.OutOrStdout(), "✓ Profile metadata entry created with version 1\n")
						log.Info(fmt.Sprintf("Profile structure created successfully: %s → HEAD", result.ProfileName))
					} else if result.ProfileCreated {
						fmt.Fprintf(cmd.OutOrStdout(), "✓ Profile created: %s (HEAD already existed)\n", result.ProfileName)
						log.Info(fmt.Sprintf("Profile created: %s (HEAD already existed)", result.ProfileName))
					} else if result.HeadCreated {
						fmt.Fprintf(cmd.OutOrStdout(), "✓ HEAD created under profile: %s (profile already existed)\n", result.ProfileName)
						fmt.Fprintf(cmd.OutOrStdout(), "✓ Profile metadata entry created with version 1\n")
						log.Info(fmt.Sprintf("HEAD created under profile: %s (profile already existed)", result.ProfileName))
					} else {
						fmt.Fprintf(cmd.OutOrStdout(), "✓ Profile structure already exists: %s → HEAD\n", result.ProfileName)
						log.Info(fmt.Sprintf("Profile structure already exists: %s → HEAD", result.ProfileName))
					}

					// Show structure update message if any changes were made
					if structureUpdated {
						fmt.Fprintf(cmd.OutOrStdout(), "✓ Profile tree data was updated\n")
					}

					// Show information about environments only in verbose mode
					if len(result.EnvironmentsCreated) > 0 {
						log.Info(fmt.Sprintf("Environments created: %v", result.EnvironmentsCreated))
					}
					if len(result.EnvironmentsExisted) > 0 {
						log.Info(fmt.Sprintf("Environments already existed: %v", result.EnvironmentsExisted))
					}
				}
			}

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
