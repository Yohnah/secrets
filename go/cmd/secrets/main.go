package main

import (
	"fmt"
	"os"

	"github.com/Yohnah/secrets/internal/cli"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Version information - injected at build time
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	// Initialize global flags
	globalFlags := &cli.GlobalFlags{}

	// Create root command
	rootCmd := &cobra.Command{
		Use:   "secrets",
		Short: "CLI tool for secrets management with KeePass integration",
		Long: `secrets is a CLI tool for managing secrets with KeePass database integration.
It provides secure storage and retrieval of secrets across different environments.

ENVIRONMENT VARIABLES:
  SECRETS_YOHNAH_CONFIG_PATH     Path to configuration file
  SECRETS_YOHNAH_DATABASE_PATH   Path to KeePass database file (.kdbx)
  SECRETS_YOHNAH_KEYFILE_PATH    Path to KeePass keyfile
  SECRETS_YOHNAH_SFC_PATH        Path to secrets.yml file
  SECRETS_YOHNAH_PASSWORD        KeePass database password

FLAGS PRECEDENCE (Security Order):
  Command line flags > config.yml > environment variables > defaults
  This order prevents attackers from using malicious environment variables.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", Version, GitCommit, BuildTime),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Initialize logger with verbose flag
			log := logger.NewLogger(globalFlags.Verbose)
			log.Debug("Verbose mode enabled")
			log.Debug(fmt.Sprintf("Using version: %s", Version))
		},
	}

	// Add global flags
	addGlobalFlags(rootCmd, globalFlags)

	// Add commands to root command
	rootCmd.AddCommand(cli.NewInitCommand())
	rootCmd.AddCommand(cli.NewShowCommand())

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// addGlobalFlags adds global flags to the root command
func addGlobalFlags(cmd *cobra.Command, flags *cli.GlobalFlags) {
	// Config file flag
	cmd.PersistentFlags().StringVarP(&flags.Config, "config", "c", "",
		"path to configuration file (env: SECRETS_YOHNAH_CONFIG_PATH)")
	viper.BindPFlag("config", cmd.PersistentFlags().Lookup("config"))
	viper.BindEnv("config", "SECRETS_YOHNAH_CONFIG_PATH")

	// Database flag
	cmd.PersistentFlags().StringVar(&flags.Database, "database", "",
		"path to KeePass database file (.kdbx) (env: SECRETS_YOHNAH_DATABASE_PATH)")
	viper.BindPFlag("database", cmd.PersistentFlags().Lookup("database"))
	viper.BindEnv("database", "SECRETS_YOHNAH_DATABASE_PATH")

	// Keyfile flag
	cmd.PersistentFlags().StringVar(&flags.Keyfile, "keyfile", "",
		"path to KeePass keyfile (env: SECRETS_YOHNAH_KEYFILE_PATH)")
	viper.BindPFlag("keyfile", cmd.PersistentFlags().Lookup("keyfile"))
	viper.BindEnv("keyfile", "SECRETS_YOHNAH_KEYFILE_PATH")

	// Secrets config file flag
	cmd.PersistentFlags().StringVarP(&flags.SecretsConfig, "secrets-config-file", "s", "",
		"path to secrets.yml file (env: SECRETS_YOHNAH_SFC_PATH)")
	viper.BindPFlag("secrets-config-file", cmd.PersistentFlags().Lookup("secrets-config-file"))
	viper.BindEnv("secrets-config-file", "SECRETS_YOHNAH_SFC_PATH")

	// Password flag (hidden for security)
	cmd.PersistentFlags().StringVar(&flags.Password, "password", "",
		"KeePass database password (env: SECRETS_YOHNAH_PASSWORD)")
	viper.BindPFlag("password", cmd.PersistentFlags().Lookup("password"))
	viper.BindEnv("password", "SECRETS_YOHNAH_PASSWORD")
	// Note: Not hiding password flag so environment variable is visible in help

	// Verbose flag
	cmd.PersistentFlags().BoolVarP(&flags.Verbose, "verbose", "v", false,
		"enable verbose output")
	viper.BindPFlag("verbose", cmd.PersistentFlags().Lookup("verbose"))

	// Force flag
	cmd.PersistentFlags().BoolVarP(&flags.Force, "force", "f", false,
		"force operation without confirmation")
	viper.BindPFlag("force", cmd.PersistentFlags().Lookup("force"))

	// Ignore git repository flag
	cmd.PersistentFlags().BoolVar(&flags.IgnoreGitRepo, "ignore-git-repository", false,
		"ignore git repository requirement and use current directory")
	viper.BindPFlag("ignore-git-repository", cmd.PersistentFlags().Lookup("ignore-git-repository"))
}
