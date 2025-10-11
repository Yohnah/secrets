package cli

import (
	"os"

	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Load profiles from secrets.yml into the database",
	Long:  `Load profiles from secrets.yml into an existing KeePass database. Run 'secrets setup' first to create the infrastructure.`,
	Run: func(cmd *cobra.Command, args []string) {
		// CliMgr creates manager context (no local flags for init)
		managers := NewManagerContext(nil)

		// Execute business logic (delegate all decisions to CORE)
		// SecretsManager will pull processed config from ConfigMgr
		if err := managers.Secrets.Init(); err != nil {
			managers.Logger.Error(err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	// No local flags for init command - only uses global flags
	// Infrastructure creation is handled by 'setup' command

	// Add command to root
	rootCmd.AddCommand(initCmd)
}
