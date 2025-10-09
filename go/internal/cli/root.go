package cli

import (
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
	flagSecretsFile  string
	flagIgnoreConfig bool
	flagIgnoreGit    bool
	flagProfileName  string
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "secrets",
	Short: "KeePass secrets manager",
	Long: `Secrets is a CLI tool for managing secrets stored in a KeePass database.

Examples:
  # Show help
  secrets --help

  # Initialize a new database
  secrets init

  # Show template
  secrets show template`,
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
	rootCmd.PersistentFlags().StringVarP(&flagProfileName, "profile-name", "p", "", "Profile name (alternative to positional argument)")
	rootCmd.PersistentFlags().StringVar(&flagDatabase, "database", ".secrets_yohnah/secrets.kdbx", "Path to KeePass database file")
	rootCmd.PersistentFlags().StringVar(&flagKeyfile, "keyfile", ".secrets_yohnah/secrets.keyfile", "Path to key file for database authentication")
	rootCmd.PersistentFlags().StringVar(&flagConfig, "config", ".secrets_yohnah/config.yml", "Path to configuration file")
	rootCmd.PersistentFlags().StringVarP(&flagSecretsFile, "secrets-file", "s", "", "Path to secrets.yml file (default: auto-detect from git root or current directory)")
	rootCmd.PersistentFlags().BoolVar(&flagIgnoreConfig, "ignore-config-file", false, "Ignore configuration file")
	rootCmd.PersistentFlags().BoolVar(&flagIgnoreGit, "ignore-git-project", false, "Ignore git project root detection (create in current directory)")

	// Custom help template to show environment variables prominently
	// Root command: Shows only "Global Flags" (all PersistentFlags)
	// Subcommands: Shows "Flags" (local flags) + "Global Flags" (inherited)
	rootCmd.SetUsageTemplate(`Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if and .HasAvailableLocalFlags .HasParent}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if or .HasAvailableInheritedFlags (not .HasParent)}}

Global Flags:
{{if .HasParent}}{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{else}}{{.PersistentFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{end}}{{if .HasHelpSubCommands}}

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

// GetGlobalFlags returns all global flag values as a struct
// Only returns flag values that were explicitly set by the user.
// For flags not set, returns empty/zero values so ConfigManager
// can apply proper precedence (FLAGS > CONFIG.YML > ENV VARS > DEFAULTS)
func GetGlobalFlags() *types.GlobalFlags {
	flags := &types.GlobalFlags{
		Verbose:          flagVerbose,
		Force:            flagForce,
		IgnoreConfigFile: flagIgnoreConfig,
		IgnoreGitProject: flagIgnoreGit,
	}

	// Only set these if explicitly provided by user (not Cobra defaults)
	if rootCmd.PersistentFlags().Changed("database") {
		flags.Database = flagDatabase
	}
	if rootCmd.PersistentFlags().Changed("keyfile") {
		flags.Keyfile = flagKeyfile
	}
	if rootCmd.PersistentFlags().Changed("config") {
		flags.Config = flagConfig
	}
	if rootCmd.PersistentFlags().Changed("secrets-file") {
		flags.SecretsFile = flagSecretsFile
	}
	if rootCmd.PersistentFlags().Changed("profile-name") {
		flags.ProfileName = flagProfileName
	}

	return flags
}
