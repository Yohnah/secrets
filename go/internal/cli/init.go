package cli

import (
	"os"

	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/spf13/cobra"
)

var (
	flagForceRecreate    bool
	flagNoCreateDatabase bool
	flagDatabaseName     string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new KeePass database",
	Long:  `Initialize a new KeePass database with the required structure for secrets management.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Create manager context with standard setup
		managers := NewManagerContext()

		// Execute business logic (delegate all decisions to CORE)
		// Pass init flags to SecretsManager
		opts := secrets.InitOptions{
			ForceRecreate:    flagForceRecreate,
			NoCreateDatabase: flagNoCreateDatabase,
			DatabaseName:     flagDatabaseName,
		}

		if err := managers.Secrets.Init(opts); err != nil {
			managers.Logger.Error(err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	// Add local flags specific to init command
	initCmd.Flags().BoolVar(&flagForceRecreate, "force-recreate", false, "Delete existing database and keyfile, then create new ones")
	initCmd.Flags().BoolVar(&flagNoCreateDatabase, "no-create-database", false, "Skip database and keyfile creation (only creates .secrets_yohnah directory and config.yml)")
	initCmd.Flags().StringVar(&flagDatabaseName, "database-name", "", "Custom name for the root group in the KeePass database (defaults to git repo name or 'Secrets')")

	// Add command to root
	rootCmd.AddCommand(initCmd)
}
