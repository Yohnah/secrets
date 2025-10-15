package cli

import (
	"os"

	"github.com/Yohnah/secrets/internal/types"
	"github.com/spf13/cobra"
)

var (
	syncedDataFlagProfile string
	syncedDataFlagOutput  string
)

var syncedDataCmd = &cobra.Command{
	Use:   "synced-data",
	Short: "Show synchronization status between secrets.yml and KeePass database",
	Long: `Check synchronization status between secrets.yml and KeePass database.

Displays for each item:
  - NAME: Item name (environment/item_name)
  - STATUS: ✓ (synced) or ✗ (not synced)
  - ISSUE: "OK" if synced, or describes what's missing (entry/key)
  - FIELD VALUE STATUS: Status of the field value in KeePass
    - "empty": Field exists but has no value
    - "has_data": Field has a value set
    - "default": Field has the default placeholder value
    - "N/A": Field does not exist or cannot be checked

Examples:
  # Check sync status (auto-detect profile if single profile)
  secrets show synced-data

  # Check specific profile
  secrets show synced-data --profile-name webapp-production

  # Output in JSON format
  secrets show synced-data -o json

  # Output in YAML format
  secrets show synced-data -o yaml`,
	Run: func(cmd *cobra.Command, args []string) {
		// CliMgr captures ALL command-specific flags and feeds them to ConfigMgr
		commandFlags := &types.CommandFlags{
			OutputFormat: syncedDataFlagOutput,
		}

		// Create manager context with captured flags
		managers := NewManagerContext(commandFlags)

		// Execute business logic (delegate all decisions to CORE)
		if err := managers.Secrets.ShowSyncedData(syncedDataFlagProfile); err != nil {
			managers.Logger.Error(err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	// Register command
	showCmd.AddCommand(syncedDataCmd)

	// Flags
	syncedDataCmd.Flags().StringVarP(&syncedDataFlagProfile, "profile-name", "p", "", "Profile name (optional, auto-detect if single profile)")
	syncedDataCmd.Flags().StringVarP(&syncedDataFlagOutput, "output", "o", "table", "Output format: table, json, yaml (default: table)")
}
