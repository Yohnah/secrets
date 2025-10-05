package cli

import (
	"os"

	"github.com/Yohnah/secrets/internal/types"
	"github.com/spf13/cobra"
)

var (
	// Global flags
	flagVerbose      bool
	flagForce        bool
	flagDatabase     string
	flagKeyfile      string
	flagConfig       string
	flagIgnoreConfig bool
	flagIgnoreGit    bool
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "secrets",
	Short: "KeePass secrets manager with snapshots support",
	Long: `Secrets is a CLI tool for managing secrets stored in a KeePass database.

Examples:
  # Show help
  secrets --help

  # Initialize a new database
  secrets init

  # Create a new snapshot
  secrets snapshots new v1.0.0

  # List all snapshots
  secrets snapshots list

  # Use custom database and keyfile
  secrets --database=/path/db.kdbx --keyfile=/path/key.file snapshots list`,
	Version: "0.1.0",
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags available to all commands
	rootCmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVarP(&flagForce, "force", "f", false, "Force operation without confirmation (non-interactive mode)")
	rootCmd.PersistentFlags().StringVar(&flagDatabase, "database", ".secrets_yohnah/secrets.kdbx", "Path to KeePass database file")
	rootCmd.PersistentFlags().StringVar(&flagKeyfile, "keyfile", ".secrets_yohnah/secrets.keyfile", "Path to key file for database authentication")
	rootCmd.PersistentFlags().StringVar(&flagConfig, "config", ".secrets_yohnah/config.yml", "Path to configuration file")
	rootCmd.PersistentFlags().BoolVar(&flagIgnoreConfig, "ignore-config-file", false, "Ignore configuration file")
	rootCmd.PersistentFlags().BoolVar(&flagIgnoreGit, "ignore-git-project", false, "Ignore git project root detection (create in current directory)")

	// Bind environment variables to flags
	bindEnvVars()

	// Custom help template to show environment variables prominently
	// Note: Only shows "Global Flags" section (not "Flags") to avoid duplication
	// since all flags are PersistentFlags (global) at root level
	rootCmd.SetUsageTemplate(`Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailablePersistentFlags}}

Global Flags:
{{.PersistentFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}

Environment Variables:
  SECRETS_YOHNAH_PASSWORD       Password for the KeePass database
  SECRETS_YOHNAH_DATABASE       Path to the KeePass database file
  SECRETS_YOHNAH_KEYFILE        Path to the key file for database authentication
  SECRETS_YOHNAH_CONFIG         Path to the configuration file
  SECRETS_YOHNAH_VERBOSE        Enable verbose mode (true/false)

Configuration Precedence:
  FLAGS > CONFIG.YML > ENV VARS > DEFAULTS
`)
}

// bindEnvVars binds environment variables to flag values if not explicitly set
func bindEnvVars() {
	// Check environment variables and set defaults if flags are not provided
	if os.Getenv("SECRETS_YOHNAH_VERBOSE") == "true" && !rootCmd.PersistentFlags().Changed("verbose") {
		flagVerbose = true
	}

	if envDB := os.Getenv("SECRETS_YOHNAH_DATABASE"); envDB != "" && !rootCmd.PersistentFlags().Changed("database") {
		flagDatabase = envDB
	}

	if envKeyfile := os.Getenv("SECRETS_YOHNAH_KEYFILE"); envKeyfile != "" && !rootCmd.PersistentFlags().Changed("keyfile") {
		flagKeyfile = envKeyfile
	}

	if envConfig := os.Getenv("SECRETS_YOHNAH_CONFIG"); envConfig != "" && !rootCmd.PersistentFlags().Changed("config") {
		flagConfig = envConfig
	}
}

// GetGlobalFlags returns all global flag values as a struct
func GetGlobalFlags() *types.GlobalFlags {
	return &types.GlobalFlags{
		Verbose:          flagVerbose,
		Force:            flagForce,
		Database:         flagDatabase,
		Keyfile:          flagKeyfile,
		Config:           flagConfig,
		IgnoreConfigFile: flagIgnoreConfig,
		IgnoreGitProject: flagIgnoreGit,
	}
}

// Helper functions to access individual flags (for CliManager)
func IsVerbose() bool {
	return flagVerbose
}

func IsForce() bool {
	return flagForce
}

func GetDatabase() string {
	return flagDatabase
}

func GetKeyfile() string {
	return flagKeyfile
}

func GetConfig() string {
	return flagConfig
}

func ShouldIgnoreConfig() bool {
	return flagIgnoreConfig
}
