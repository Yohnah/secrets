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
	Use:   "list [profile_name|all]",
	Short: "List snapshots",
	Long:  "List all snapshots for a specific profile or all profiles. Use 'all' to list snapshots from all profiles",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Get profile name from args (optional, default "all")
		profileName := "all"
		if len(args) > 0 {
			profileName = args[0]
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
	Use:   "new <profile_name>",
	Short: "Create a new snapshot",
	Long:  "Create a new snapshot by cloning HEAD to v{current_version} and incrementing HEAD version",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Get profile name from args (required)
		profileName := args[0]

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

func init() {
	// Add list subcommand to snapshots
	snapshotsCmd.AddCommand(snapshotsListCmd)

	// Add new subcommand to snapshots
	snapshotsCmd.AddCommand(snapshotsNewCmd)

	// Add flags to list command
	snapshotsListCmd.Flags().StringVarP(&flagSnapshotsOutput, "output", "o", "table", "Output format: table, json, yaml")

	// Register snapshots command to root
	rootCmd.AddCommand(snapshotsCmd)
}
