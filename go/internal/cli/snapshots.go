package cli

import (
	"os"

	"github.com/Yohnah/secrets/internal/types"
	"github.com/spf13/cobra"
)

var (
	// Snapshots list flags
	flagSnapshotsOutput string
)

// snapshotsCmd is the main snapshots command
var snapshotsCmd = &cobra.Command{
	Use:   "snapshots",
	Short: "Manage profile snapshots",
	Long:  "List snapshots of profile versions in the KeePass database",
}

// snapshotsListCmd lists all snapshots
var snapshotsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List snapshots",
	Long: `List all snapshots for a specific profile or all profiles.

Profile name can be specified via:
  1. Flag: -p/--profile-name (optional, defaults to "all")
  2. Positional argument (legacy, deprecated)

Examples:
  secrets snapshots list                 # List all snapshots
  secrets snapshots list -p webapp-prod  # List for specific profile via flag
  secrets snapshots list webapp-prod     # List for specific profile (legacy)`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Determine profile name from flag or positional argument
		var profileName string

		if flagProfileName != "" {
			// Priority 1: Use flag if provided
			profileName = flagProfileName
		} else if len(args) > 0 {
			// Priority 2: Legacy positional argument (backward compatibility)
			profileName = args[0]
		} else {
			// Default: show all profiles
			profileName = "all"
		}

		// Create command flags
		commandFlags := &types.CommandFlags{
			OutputFormat: flagSnapshotsOutput,
		}

		// Create manager context with captured flags
		managers := NewManagerContext(commandFlags)

		// Execute list command (delegate to CORE)
		if err := managers.Secrets.SnapshotsList(profileName); err != nil {
			managers.Logger.Error(err.Error())
			os.Exit(1)
		}
	},
}

// snapshotsNewCmd creates a new snapshot
var snapshotsNewCmd = &cobra.Command{
	Use:   "new",
	Short: "Create a new snapshot",
	Long: `Create a new snapshot by cloning HEAD to v{current_version} and incrementing HEAD version.

Profile name can be specified via:
  1. Flag: -p/--profile-name (required)
  2. Positional argument (legacy, deprecated)

Examples:
  secrets snapshots new -p webapp-prod  # Via flag
  secrets snapshots new webapp-prod     # Legacy style`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Determine profile name from flag or positional argument
		var profileName string

		if flagProfileName != "" {
			// Priority 1: Use flag if provided
			profileName = flagProfileName
		} else if len(args) > 0 {
			// Priority 2: Legacy positional argument (backward compatibility)
			profileName = args[0]
		} else {
			// Error: profile name is required
			managers := NewManagerContext(&types.CommandFlags{})
			managers.Logger.Error("profile name is required (use -p/--profile-name flag or positional argument)")
			os.Exit(1)
		}

		// Create command flags (no specific flags for this command)
		commandFlags := &types.CommandFlags{}

		// Create manager context
		managers := NewManagerContext(commandFlags)

		// Execute new command (delegate to CORE)
		if err := managers.Secrets.SnapshotsNew(profileName); err != nil {
			managers.Logger.Error(err.Error())
			os.Exit(1)
		}
	},
}

// snapshotsRestoreCmd restores a snapshot to HEAD
var snapshotsRestoreCmd = &cobra.Command{
	Use:   "restore <version>",
	Short: "Restore a snapshot to HEAD",
	Long: `Restore a snapshot by renaming current HEAD to v{current_version} and cloning the specified version to new HEAD with incremented version.

Profile name can be specified via:
  1. Flag: -p/--profile-name (required)
  2. Positional argument (legacy, deprecated)

Examples:
  secrets snapshots restore -p webapp-prod v3  # Via flag
  secrets snapshots restore webapp-prod v3     # Legacy style`,
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		// Determine profile name and version from flag/args
		var profileName, version string

		if flagProfileName != "" {
			// Priority 1: Use flag if provided
			profileName = flagProfileName
			if len(args) < 1 {
				managers := NewManagerContext(&types.CommandFlags{})
				managers.Logger.Error("version is required")
				os.Exit(1)
			}
			version = args[0]
		} else if len(args) == 2 {
			// Priority 2: Legacy positional arguments (backward compatibility)
			profileName = args[0]
			version = args[1]
		} else if len(args) == 1 {
			// Ambiguous: only one argument without flag
			managers := NewManagerContext(&types.CommandFlags{})
			managers.Logger.Error("profile name must be specified via -p/--profile-name flag or as first positional argument")
			os.Exit(1)
		} else {
			// No arguments at all
			managers := NewManagerContext(&types.CommandFlags{})
			managers.Logger.Error("profile name and version are required")
			os.Exit(1)
		}

		// Create command flags (no specific flags for this command)
		commandFlags := &types.CommandFlags{}

		// Create manager context
		managers := NewManagerContext(commandFlags)

		// Execute restore command (delegate to CORE)
		if err := managers.Secrets.SnapshotsRestore(profileName, version); err != nil {
			managers.Logger.Error(err.Error())
			os.Exit(1)
		}
	},
}

// snapshotsDeleteCmd deletes a specific snapshot version
var snapshotsDeleteCmd = &cobra.Command{
	Use:   "delete <version>",
	Short: "Delete a snapshot version",
	Long: `Delete a specific snapshot version from a profile. HEAD cannot be deleted. This operation is permanent.

Profile name can be specified via:
  1. Flag: -p/--profile-name (required)
  2. Positional argument (legacy, deprecated)

Examples:
  secrets snapshots delete -p webapp-prod v2  # Via flag
  secrets snapshots delete webapp-prod v2     # Legacy style`,
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		// Determine profile name and version from flag/args
		var profileName, version string

		if flagProfileName != "" {
			// Priority 1: Use flag if provided
			profileName = flagProfileName
			if len(args) < 1 {
				managers := NewManagerContext(&types.CommandFlags{})
				managers.Logger.Error("version is required")
				os.Exit(1)
			}
			version = args[0]
		} else if len(args) == 2 {
			// Priority 2: Legacy positional arguments (backward compatibility)
			profileName = args[0]
			version = args[1]
		} else if len(args) == 1 {
			// Ambiguous: only one argument without flag
			managers := NewManagerContext(&types.CommandFlags{})
			managers.Logger.Error("profile name must be specified via -p/--profile-name flag or as first positional argument")
			os.Exit(1)
		} else {
			// No arguments at all
			managers := NewManagerContext(&types.CommandFlags{})
			managers.Logger.Error("profile name and version are required")
			os.Exit(1)
		}

		// Create command flags (no specific flags for this command)
		commandFlags := &types.CommandFlags{}

		// Create manager context
		managers := NewManagerContext(commandFlags)

		// Execute delete command (delegate to CORE)
		if err := managers.Secrets.SnapshotsDelete(profileName, version); err != nil {
			managers.Logger.Error(err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	// Add list subcommand to snapshots
	snapshotsCmd.AddCommand(snapshotsListCmd)

	// Add new subcommand to snapshots
	snapshotsCmd.AddCommand(snapshotsNewCmd)

	// Add restore subcommand to snapshots
	snapshotsCmd.AddCommand(snapshotsRestoreCmd)

	// Add delete subcommand to snapshots
	snapshotsCmd.AddCommand(snapshotsDeleteCmd)

	// Add flags to list command
	snapshotsListCmd.Flags().StringVarP(&flagSnapshotsOutput, "output", "o", "table", "Output format: table, json, yaml")

	// Register snapshots command to root
	rootCmd.AddCommand(snapshotsCmd)
}
