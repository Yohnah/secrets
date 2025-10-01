package cli

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// NewSnapshotCommand creates the snapshot command with subcommands
func NewSnapshotCommand(app *CLIApp) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Manage version snapshots of your secrets",
		Long: `Manage version snapshots of your secrets.

Available commands:
  new     Create a new snapshot from current HEAD
  delete  Delete an existing snapshot version
  list    List all existing snapshots

Examples:
  secrets snapshot new                 # Create snapshot from current HEAD version
  secrets snapshot delete v2.0.0      # Delete specific snapshot version
  secrets snapshot list               # List all existing snapshots`,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	// Add subcommands
	cmd.AddCommand(NewSnapshotNewCommand(app))
	cmd.AddCommand(NewSnapshotDeleteCommand(app))
	cmd.AddCommand(NewSnapshotListCommand(app))

	return cmd
}

// NewSnapshotNewCommand creates the 'snapshot new' subcommand
func NewSnapshotNewCommand(app *CLIApp) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Create a new snapshot from current HEAD",
		Long: `Create a new snapshot from the current HEAD state.

This command will:
1. Clone the current HEAD group and all its contents
2. Create a new group with the current version name (from HEAD's version entry)
3. Update the HEAD's version entry to the next version

The snapshot preserves all environments, entries, and their values at the time of creation.
This allows you to maintain version history of your secrets configuration.

Example:
  secrets snapshot new                 # Create new snapshot and increment HEAD version
  secrets snapshot new --force         # Create without confirmation prompt`,
		Run: func(cmd *cobra.Command, args []string) {
			runSnapshotNew(app, cmd, args)
		},
	}
	cmd.Flags().BoolP("force", "f", false, "Skip confirmation prompt")
	return cmd
}

// NewSnapshotDeleteCommand creates the 'snapshot delete' subcommand
func NewSnapshotDeleteCommand(app *CLIApp) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <version>",
		Short: "Delete an existing snapshot version",
		Long: `Delete an existing snapshot version.

This command will permanently delete the specified version group and all its contents.
The HEAD group cannot be deleted and is protected.

Examples:
  secrets snapshot delete v2          # Delete snapshot version v2
  secrets snapshot delete v10         # Delete snapshot version v10
  secrets snapshot delete v1 --force  # Delete without confirmation prompt`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			runSnapshotDelete(app, cmd, args)
		},
	}
	cmd.Flags().BoolP("force", "f", false, "Skip confirmation prompt")
	return cmd
}

// NewSnapshotListCommand creates a new snapshot list command
func NewSnapshotListCommand(app *CLIApp) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all snapshots",
		Run: func(cmd *cobra.Command, args []string) {
			runSnapshotList(app)
		},
	}
	return cmd
}

// runSnapshotNew handles the 'snapshot new' command execution
func runSnapshotNew(app *CLIApp, cmd *cobra.Command, args []string) {
	logger := NewLogger(app.IsVerbose())
	gitFinder := NewGitRootFinder(logger)
	configManager := NewConfigManager(logger)
	passwordProvider := NewPasswordProvider(logger)
	confirmationProvider := NewConfirmationProvider(logger)
	keepassManager := NewKeePassManager(logger)
	secretsConfigManager := NewSecretsConfigManager(logger)

	logger.Debug("Snapshot new command started")

	// Ask for confirmation unless force flag is used
	forceFlag, _ := cmd.Flags().GetBool("force")
	if !forceFlag {
		confirmed, err := confirmationProvider.Confirm("Are you sure you want to create a new snapshot from current HEAD?")
		if err != nil {
			logger.Error("Failed to get confirmation: " + err.Error())
			return
		}
		if !confirmed {
			logger.Print("Snapshot creation cancelled.")
			return
		}
	}

	// Find git root
	gitRoot, err := gitFinder.FindGitRoot()
	if err != nil {
		logger.Error("Failed to find git repository root: " + err.Error())
		return
	}

	// Load secrets.yml
	var secretsConfigPath string
	if customSecretsConfig := app.GetSecretsConfigFile(); customSecretsConfig != "" {
		secretsConfigPath = customSecretsConfig
	} else {
		secretsConfigPath, err = secretsConfigManager.FindSecretsConfigFile(gitRoot)
		if err != nil {
			logger.Error("Failed to find secrets.yml: " + err.Error())
			return
		}
	}

	// Load the secrets config to get profile
	secretsConfig, err := secretsConfigManager.LoadSecretsConfig(secretsConfigPath)
	if err != nil {
		logger.Error("Failed to load secrets config: " + err.Error())
		return
	}

	// Log profile for debugging
	logger.Debug("Profile: " + secretsConfig.Metadata.Profile)

	// Load the main config for database paths
	var configPath string
	if customConfig := app.GetConfig(); customConfig != "" {
		configPath = customConfig
	} else {
		configPath = filepath.Join(gitRoot, ".secrets_yohnah", "config.yml")
	}

	config, err := configManager.LoadConfig(configPath)
	if err != nil {
		logger.Error("Failed to load configuration: " + err.Error())
		return
	}

	// Resolve paths
	secretsDir := filepath.Join(gitRoot, ".secrets_yohnah")
	dbPath, keyfilePath := resolveConfigPaths(secretsDir, config)

	// Validate paths
	if err := keepassManager.ValidatePaths(dbPath, keyfilePath); err != nil {
		logger.Error("Invalid paths: " + err.Error())
		return
	}

	// Check if database exists
	if !keepassManager.DatabaseExists(dbPath) {
		logger.Error("KeePass database does not exist. Run 'secrets init' first.")
		return
	}

	// Get password
	password, err := passwordProvider.GetPassword("Enter password for KeePass database: ")
	if err != nil {
		logger.Error("Failed to get password: " + err.Error())
		return
	}

	// Create snapshot
	result, err := keepassManager.CreateSnapshot(dbPath, keyfilePath, password, secretsConfig.Metadata.Profile)
	if err != nil {
		logger.Error("Failed to create snapshot: " + err.Error())
		return
	}

	// Show success messages with version information
	logger.Success("Snapshot created successfully")
	logger.Print("HEAD -> " + result.CreatedVersion)
	logger.Print("HEAD is now " + result.NewHeadVersion)
}

// runSnapshotDelete handles the 'snapshot delete' command execution
func runSnapshotDelete(app *CLIApp, cmd *cobra.Command, args []string) {
	logger := NewLogger(app.IsVerbose())
	gitFinder := NewGitRootFinder(logger)
	configManager := NewConfigManager(logger)
	passwordProvider := NewPasswordProvider(logger)
	confirmationProvider := NewConfirmationProvider(logger)
	keepassManager := NewKeePassManager(logger)
	secretsConfigManager := NewSecretsConfigManager(logger)

	version := args[0]
	logger.Debug("Snapshot delete command started for version: " + version)

	// Ask for confirmation unless force flag is used
	forceFlag, _ := cmd.Flags().GetBool("force")
	if !forceFlag {
		confirmed, err := confirmationProvider.Confirm("Are you sure you want to delete snapshot '" + version + "'? This action cannot be undone.")
		if err != nil {
			logger.Error("Failed to get confirmation: " + err.Error())
			return
		}
		if !confirmed {
			logger.Print("Snapshot deletion cancelled.")
			return
		}
	}

	// Validate version format
	if !isValidVersionFormat(version) {
		logger.Error("Invalid version format. Expected format: v1, v2, v3, etc.")
		return
	}

	// Protect HEAD from deletion
	if strings.ToUpper(version) == "HEAD" {
		logger.Error("Cannot delete HEAD group. HEAD is protected and cannot be removed.")
		return
	}

	// Find git root
	gitRoot, err := gitFinder.FindGitRoot()
	if err != nil {
		logger.Error("Failed to find git repository root: " + err.Error())
		return
	}

	// Load secrets.yml
	var secretsConfigPath string
	if customSecretsConfig := app.GetSecretsConfigFile(); customSecretsConfig != "" {
		secretsConfigPath = customSecretsConfig
	} else {
		secretsConfigPath, err = secretsConfigManager.FindSecretsConfigFile(gitRoot)
		if err != nil {
			logger.Error("Failed to find secrets.yml: " + err.Error())
			return
		}
	}

	// Load the secrets config to get profile
	secretsConfig, err := secretsConfigManager.LoadSecretsConfig(secretsConfigPath)
	if err != nil {
		logger.Error("Failed to load secrets config: " + err.Error())
		return
	}

	// Load the main config for database paths
	var configPath string
	if customConfig := app.GetConfig(); customConfig != "" {
		configPath = customConfig
	} else {
		configPath = filepath.Join(gitRoot, ".secrets_yohnah", "config.yml")
	}

	config, err := configManager.LoadConfig(configPath)
	if err != nil {
		logger.Error("Failed to load configuration: " + err.Error())
		return
	}

	// Resolve paths
	secretsDir := filepath.Join(gitRoot, ".secrets_yohnah")
	dbPath, keyfilePath := resolveConfigPaths(secretsDir, config)

	// Validate paths
	if err := keepassManager.ValidatePaths(dbPath, keyfilePath); err != nil {
		logger.Error("Invalid paths: " + err.Error())
		return
	}

	// Check if database exists
	if !keepassManager.DatabaseExists(dbPath) {
		logger.Error("KeePass database does not exist. Run 'secrets init' first.")
		return
	}

	// Get password
	password, err := passwordProvider.GetPassword("Enter password for KeePass database: ")
	if err != nil {
		logger.Error("Failed to get password: " + err.Error())
		return
	}

	// Delete snapshot
	if err := keepassManager.DeleteSnapshot(dbPath, keyfilePath, password, secretsConfig.Metadata.Profile, version); err != nil {
		logger.Error("Failed to delete snapshot: " + err.Error())
		return
	}

	logger.Success("Snapshot " + version + " deleted successfully")
}

// runSnapshotList handles the snapshot list command
func runSnapshotList(app *CLIApp) {
	logger := NewLogger(app.IsVerbose())
	gitFinder := NewGitRootFinder(logger)
	configManager := NewConfigManager(logger)
	passwordProvider := NewPasswordProvider(logger)
	keepassManager := NewKeePassManager(logger)
	secretsConfigManager := NewSecretsConfigManager(logger)

	logger.Debug("Snapshot list command started")

	// Find git root
	gitRoot, err := gitFinder.FindGitRoot()
	if err != nil {
		logger.Error("Failed to find git repository root: " + err.Error())
		return
	}

	// Load secrets.yml
	var secretsConfigPath string
	if customSecretsConfig := app.GetSecretsConfigFile(); customSecretsConfig != "" {
		secretsConfigPath = customSecretsConfig
	} else {
		secretsConfigPath, err = secretsConfigManager.FindSecretsConfigFile(gitRoot)
		if err != nil {
			logger.Error("Failed to find secrets.yml: " + err.Error())
			return
		}
	}

	// Load the secrets config to get profile
	secretsConfig, err := secretsConfigManager.LoadSecretsConfig(secretsConfigPath)
	if err != nil {
		logger.Error("Failed to load secrets config: " + err.Error())
		return
	}

	// Load the main config for database paths
	var configPath string
	if customConfig := app.GetConfig(); customConfig != "" {
		configPath = customConfig
	} else {
		configPath = filepath.Join(gitRoot, ".secrets_yohnah", "config.yml")
	}

	config, err := configManager.LoadConfig(configPath)
	if err != nil {
		logger.Error("Failed to load configuration: " + err.Error())
		return
	}

	// Resolve paths
	secretsDir := filepath.Join(gitRoot, ".secrets_yohnah")
	dbPath, keyfilePath := resolveConfigPaths(secretsDir, config)

	// Validate paths
	if err := keepassManager.ValidatePaths(dbPath, keyfilePath); err != nil {
		logger.Error("Invalid paths: " + err.Error())
		return
	}

	// Check if database exists
	if !keepassManager.DatabaseExists(dbPath) {
		logger.Error("KeePass database does not exist. Run 'secrets init' first.")
		return
	}

	// Get password
	password, err := passwordProvider.GetPassword("Enter password for KeePass database: ")
	if err != nil {
		logger.Error("Failed to get password: " + err.Error())
		return
	}

	// List snapshots
	snapshots, err := keepassManager.ListSnapshots(dbPath, keyfilePath, password, secretsConfig.Metadata.Profile)
	if err != nil {
		logger.Error("Failed to list snapshots: " + err.Error())
		return
	}

	if len(snapshots) == 0 {
		logger.Print("No snapshots found")
		return
	}

	logger.Print("Available snapshots:")
	for _, snapshot := range snapshots {
		logger.Print("  - " + snapshot)
	}
}

// isValidVersionFormat validates the version format (v1, v2, v3, etc.)
func isValidVersionFormat(version string) bool {
	if !strings.HasPrefix(strings.ToLower(version), "v") {
		return false
	}
	
	numberPart := version[1:]
	if _, err := strconv.Atoi(numberPart); err != nil {
		return false
	}
	
	return true
}
