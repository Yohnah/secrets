package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	configPkg "github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NewSnapshotsCommand creates the snapshots command
// Follows SRP - Single Responsibility Principle: only handles snapshots command creation
func NewSnapshotsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snapshots",
		Short: "Manage snapshots of your secrets",
		Long: `Manage snapshots of your secrets stored in KeePass database.

Snapshots are versioned copies of your HEAD configuration that allow you to:
- Create backups before making changes
- Track history of your secrets configuration
- Restore previous versions if needed

Available subcommands:
  new     Create a new snapshot from current HEAD
  list    List all available snapshots
  delete  Delete a specific snapshot`,
	}

	// Add subcommands
	cmd.AddCommand(NewSnapshotsNewCommand())
	cmd.AddCommand(NewSnapshotsDeleteCommand())
	cmd.AddCommand(NewSnapshotsListCommand())

	return cmd
}

// NewSnapshotsNewCommand creates the snapshots new subcommand
// Follows SRP - Single Responsibility Principle: only handles snapshot creation command
func NewSnapshotsNewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Create a new snapshot from current HEAD",
		Long: `Create a new snapshot from current HEAD configuration.

This command will:
1. Read secrets.yml to get the profile name
2. Open KeePass database
3. Find HEAD under the specified profile
4. Calculate next version number (v1, v2, v3...)
5. Confirm snapshot creation with user
6. Clone HEAD to new snapshot version
7. Save database

The snapshot will be created as a sibling of HEAD under your profile.

Examples:
  secrets snapshot new                    # Create snapshot with confirmation
  secrets snapshot new --force            # Create snapshot without confirmation
  secrets snapshot new --verbose          # Create snapshot with verbose output`,
		SilenceUsage:  true, // Don't show usage on execution errors
		SilenceErrors: true, // Don't show errors twice
		RunE: func(cmd *cobra.Command, args []string) error {
			// Initialize managers following DDD
			configMgr := configPkg.NewConfigManager()
			dbMgr := keepass.NewDatabaseManager()

			// Get command-specific flags
			verbose, _ := cmd.Flags().GetBool("verbose")
			force, _ := cmd.Flags().GetBool("force")

			// Detect global flags if explicitly set
			var databaseFlag, keyfileFlag string
			if cmd.Parent() != nil && cmd.Parent().Parent() != nil {
				if cmd.Parent().Parent().Flags().Changed("database") {
					databaseFlag = viper.GetString("database")
				}
				if cmd.Parent().Parent().Flags().Changed("keyfile") {
					keyfileFlag = viper.GetString("keyfile")
				}
			}

			// Load configuration with automatic precedence
			cfg, err := configMgr.Load(configPkg.ConfigOptions{
				DatabaseFlag: databaseFlag,
				KeyfileFlag:  keyfileFlag,
				VerboseFlag:  verbose,
				ForceFlag:    force,
				ConfigPath:   "",
				BasePath:     ".secrets_yohnah",
			})
			if err != nil {
				return fmt.Errorf("error loading configuration: %w", err)
			}

			// Initialize logger with configuration from ConfigManager
			log := logger.NewLogger(cfg.Verbose)

			// Initialize prompter with configuration from ConfigManager
			prompter := prompt.NewInteractivePrompter(cfg.Force)

			// Initialize SecretsManager with all dependencies (DIP)
			// SecretsManager receives pre-configured managers to make business decisions
			secretsMgr := secrets.NewSecretsManager(dbMgr, log, prompter, nil)

			// Load secrets.yml to get profile name
			secretsConfig, err := secretsMgr.LoadAndValidateSecretsFile("")
			if err != nil {
				return fmt.Errorf("failed to load secrets.yml: %w", err)
			}

			if secretsConfig.Metadata.Profile == "" {
				return fmt.Errorf("profile name not found in secrets.yml metadata")
			}

			// Create snapshot through SecretsManager (business logic layer)
			// SecretsManager handles: password retrieval, validation, version calculation, user confirmation, cloning
			// Following DDD: SecretsManager is the CORE that takes ALL business decisions
			result, err := secretsMgr.CreateSnapshot(cfg.DatabasePath, cfg.KeyfilePath, secretsConfig.Metadata.Profile)
			if err != nil {
				return err
			}

			// Display result to user
			if result.Created {
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Snapshot created: %s\n", result.Version)
				log.Info(fmt.Sprintf("Snapshot %s created successfully for profile %s", result.Version, result.ProfileName))
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "Snapshot creation cancelled by user.")
			}

			return nil
		},
	}

	// Add command-specific flags
	cmd.Flags().BoolP("force", "f", false, "force operation without confirmation")
	cmd.Flags().BoolP("verbose", "v", false, "verbose output")

	return cmd
}

// NewSnapshotsDeleteCommand creates the snapshots delete subcommand
// Follows SRP - Single Responsibility Principle: only handles snapshot deletion command
func NewSnapshotsDeleteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <version>",
		Short: "Delete a specific snapshot version",
		Long: `Delete a specific snapshot version from the database.

This command will:
1. Read secrets.yml to get the profile name
2. Open KeePass database
3. Validate the version exists and is not HEAD
4. Confirm deletion with user
5. Delete the snapshot group
6. Save database

IMPORTANT: HEAD cannot be deleted. Only snapshot versions (v1, v2, v3...) can be removed.

Examples:
  secrets snapshot delete v1              # Delete v1 with confirmation
  secrets snapshot delete v2 --force      # Delete v2 without confirmation
  secrets snapshot delete v3 --verbose    # Delete v3 with verbose output`,
		Args:          cobra.ExactArgs(1), // Require exactly one argument (version)
		SilenceUsage:  true,               // Don't show usage on execution errors
		SilenceErrors: true,               // Don't show errors twice
		RunE: func(cmd *cobra.Command, args []string) error {
			version := args[0]

			// Initialize managers following DDD
			configMgr := configPkg.NewConfigManager()
			dbMgr := keepass.NewDatabaseManager()

			// Get command-specific flags
			verbose, _ := cmd.Flags().GetBool("verbose")
			force, _ := cmd.Flags().GetBool("force")

			// Detect global flags if explicitly set
			var databaseFlag, keyfileFlag string
			if cmd.Parent() != nil && cmd.Parent().Parent() != nil {
				if cmd.Parent().Parent().Flags().Changed("database") {
					databaseFlag = viper.GetString("database")
				}
				if cmd.Parent().Parent().Flags().Changed("keyfile") {
					keyfileFlag = viper.GetString("keyfile")
				}
			}

			// Load configuration with automatic precedence
			cfg, err := configMgr.Load(configPkg.ConfigOptions{
				DatabaseFlag: databaseFlag,
				KeyfileFlag:  keyfileFlag,
				VerboseFlag:  verbose,
				ForceFlag:    force,
				ConfigPath:   "",
				BasePath:     ".secrets_yohnah",
			})
			if err != nil {
				return fmt.Errorf("error loading configuration: %w", err)
			}

			// Initialize logger with configuration from ConfigManager
			log := logger.NewLogger(cfg.Verbose)

			// Initialize prompter with configuration from ConfigManager
			prompter := prompt.NewInteractivePrompter(cfg.Force)

			// Initialize SecretsManager with all dependencies (DIP)
			// SecretsManager receives pre-configured managers to make business decisions
			secretsMgr := secrets.NewSecretsManager(dbMgr, log, prompter, nil)

			// Load secrets.yml to get profile name
			secretsConfig, err := secretsMgr.LoadAndValidateSecretsFile("")
			if err != nil {
				return fmt.Errorf("failed to load secrets.yml: %w", err)
			}

			if secretsConfig.Metadata.Profile == "" {
				return fmt.Errorf("profile name not found in secrets.yml metadata")
			}

			// Delete snapshot through SecretsManager (business logic layer)
			// SecretsManager handles: password retrieval, validation, HEAD protection, user confirmation, deletion
			// Following DDD: SecretsManager is the CORE that takes ALL business decisions
			result, err := secretsMgr.DeleteSnapshot(cfg.DatabasePath, cfg.KeyfilePath, secretsConfig.Metadata.Profile, version)
			if err != nil {
				return err
			}

			// Display result to user
			if result.Deleted {
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Snapshot deleted: %s\n", result.Version)
				log.Info(fmt.Sprintf("Snapshot %s deleted successfully from profile %s", result.Version, result.ProfileName))
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "Snapshot deletion cancelled by user.")
			}

			return nil
		},
	}

	// Add command-specific flags
	cmd.Flags().BoolP("force", "f", false, "force operation without confirmation")
	cmd.Flags().BoolP("verbose", "v", false, "verbose output")

	return cmd
}

// NewSnapshotsListCommand creates the snapshots list subcommand
// Follows SRP - Single Responsibility Principle: only handles snapshot listing command
func NewSnapshotsListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all available snapshots with statistics",
		Long: `List all available snapshots with detailed information and statistics.

This command will:
1. Read secrets.yml to get the profile name
2. Open KeePass database
3. Find all snapshots under the profile
4. Calculate statistics (environments, entries per environment)
5. Display results in the specified format (table or json)

The output includes:
- Version: Snapshot version number (v1, v2, v3...)
- Since: Date and time from snapshot metadata
- Environments: Number of environments in the snapshot
- Total Entries: Total number of entries across all environments
- Entries by Environment: Detailed breakdown per environment

Examples:
  secrets snapshots list                    # List with table format (default)
  secrets snapshots list --output json      # List with JSON format
  secrets snapshots list -o json            # Same as above (short flag)
  secrets snapshots list --verbose          # List with verbose output`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			configMgr := configPkg.NewConfigManager()
			dbMgr := keepass.NewDatabaseManager()

			verbose, _ := cmd.Flags().GetBool("verbose")
			extended, _ := cmd.Flags().GetBool("extended")
			outputFormat, _ := cmd.Flags().GetString("output")

			var databaseFlag, keyfileFlag string
			if cmd.Parent() != nil && cmd.Parent().Parent() != nil {
				if cmd.Parent().Parent().Flags().Changed("database") {
					databaseFlag = viper.GetString("database")
				}
				if cmd.Parent().Parent().Flags().Changed("keyfile") {
					keyfileFlag = viper.GetString("keyfile")
				}
			}

			// ConfigManager is the SINGLE SOURCE OF TRUTH for ALL configuration
			// Pass extended flag to ConfigManager for proper precedence handling
			cfg, err := configMgr.Load(configPkg.ConfigOptions{
				DatabaseFlag: databaseFlag,
				KeyfileFlag:  keyfileFlag,
				VerboseFlag:  verbose,
				ExtendedFlag: extended,
				ConfigPath:   "",
				BasePath:     ".secrets_yohnah",
			})
			if err != nil {
				return fmt.Errorf("error loading configuration: %w", err)
			}

			log := logger.NewLogger(cfg.Verbose)
			prompter := prompt.NewInteractivePrompter(cfg.Force)
			secretsMgr := secrets.NewSecretsManager(dbMgr, log, prompter, nil)

			secretsConfig, err := secretsMgr.LoadAndValidateSecretsFile("")
			if err != nil {
				return fmt.Errorf("failed to load secrets.yml: %w", err)
			}

			if secretsConfig.Metadata.Profile == "" {
				return fmt.Errorf("profile name not found in secrets.yml metadata")
			}

			// Extract extended from Config (processed by ConfigManager)
			// Following architecture: CLI extracts values from Config, passes to SecretsManager
			result, err := secretsMgr.ListSnapshots(cfg.DatabasePath, cfg.KeyfilePath, secretsConfig.Metadata.Profile, cfg.Extended)
			if err != nil {
				return err
			}

			if outputFormat == "json" {
				output, err := formatJSON(result)
				if err != nil {
					return fmt.Errorf("failed to format JSON: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), output)
			} else {
				output := formatTable(result)
				fmt.Fprint(cmd.OutOrStdout(), output)
			}

			return nil
		},
	}

	cmd.Flags().StringP("output", "o", "table", "output format: table or json")
	cmd.Flags().BoolP("extended", "e", false, "show extended information (entries per environment breakdown)")
	cmd.Flags().BoolP("verbose", "v", false, "verbose output")

	return cmd
}

// formatJSON formats the snapshots list result as JSON
// Follows SRP - Single Responsibility Principle: only handles JSON formatting
func formatJSON(result *secrets.SnapshotsListResult) (string, error) {
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return string(jsonData), nil
}

// formatTable formats the snapshots list result as a human-readable table
// Follows SRP - Single Responsibility Principle: only handles table formatting
func formatTable(result *secrets.SnapshotsListResult) string {
	var output strings.Builder

	output.WriteString(fmt.Sprintf("Profile: %s\n\n", result.ProfileName))

	if len(result.Snapshots) == 0 {
		output.WriteString("No snapshots found.\n")
		return output.String()
	}

	// Table header
	output.WriteString(fmt.Sprintf("%-10s %-25s %-15s %-15s\n", "VERSION", "SINCE", "ENVIRONMENTS", "TOTAL ENTRIES"))
	output.WriteString(strings.Repeat("-", 70) + "\n")

	// Table rows
	for _, snapshot := range result.Snapshots {
		since := snapshot.Since
		if since == "" {
			since = "N/A"
		}

		output.WriteString(fmt.Sprintf("%-10s %-25s %-15d %-15d\n",
			snapshot.Version,
			since,
			snapshot.Environments,
			snapshot.TotalEntries,
		))

		// Show entries per environment breakdown if data was provided by SecretsManager
		if len(snapshot.EntriesByEnv) > 0 {
			for envName, count := range snapshot.EntriesByEnv {
				output.WriteString(fmt.Sprintf("  └─ %s: %d entries\n", envName, count))
			}
		}
	}

	output.WriteString("\n")
	return output.String()
}
