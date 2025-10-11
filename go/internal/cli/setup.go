package cli

import (
	"os"

	"github.com/Yohnah/secrets/internal/types"
	"github.com/spf13/cobra"
)

var (
	setupFlagForceRecreate    bool
	setupFlagNoCreateDatabase bool
	setupFlagDatabaseName     string
	setupFlagSetupDirInHome   bool
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Setup the secrets management system (directory + files + database)",
	Long: `Setup creates the complete secrets management system including:
  - .secrets_yohnah directory
  - config.yml configuration file
  - Cryptographically secure keyfile
  - KeePass encrypted database
  - Optional: Load profiles from secrets.yml

This command performs the full initialization in one step.
Use 'secrets init' if you only want to create the directory structure.`,
	Run: func(cmd *cobra.Command, args []string) {
		// CliMgr captures ALL command-specific flags and feeds them to ConfigMgr
		commandFlags := &types.CommandFlags{
			ForceRecreate:    setupFlagForceRecreate,
			NoCreateDatabase: setupFlagNoCreateDatabase,
			DatabaseName:     setupFlagDatabaseName,
			SetupDirInHome:   setupFlagSetupDirInHome,
		}

		// Create manager context with captured flags
		managers := NewManagerContext(commandFlags)

		// Execute business logic (delegate all decisions to CORE)
		// SecretsManager will pull processed config from ConfigMgr
		// Setup only creates infrastructure (no profile loading)
		if err := managers.Secrets.Setup(); err != nil {
			managers.Logger.Error(err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	// Add local flags specific to setup command
	setupCmd.Flags().BoolVar(&setupFlagForceRecreate, "force-recreate", false, "Delete existing database and keyfile, then create new ones")
	setupCmd.Flags().BoolVar(&setupFlagNoCreateDatabase, "no-create-database", false, "Skip database and keyfile creation (only creates .secrets_yohnah directory and config.yml)")
	setupCmd.Flags().StringVar(&setupFlagDatabaseName, "database-name", "", "Custom name for the root group in the KeePass database (defaults to git repo name or 'Secrets')")
	setupCmd.Flags().BoolVar(&setupFlagSetupDirInHome, "setup-dir-in-home", false, "Create setup directory in home (~/.yohnah/secrets) instead of project directory")

	// Add command to root
	rootCmd.AddCommand(setupCmd)
}
