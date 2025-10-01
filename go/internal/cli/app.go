// Package cli provides the command-line interface following SOLID principles
package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Version information - set by main package
var (
	appVersion   = "dev"
	appGitCommit = "unknown"
	appBuildTime = "unknown"
)

// SetVersionInfo sets version information from main package
func SetVersionInfo(version, gitCommit, buildTime string) {
	appVersion = version
	appGitCommit = gitCommit
	appBuildTime = buildTime
}

// App interface follows ISP - Interface Segregation Principle
type App interface {
	Execute() error
}

// CLIApp follows SRP - Single Responsibility Principle (manages CLI lifecycle)
type CLIApp struct {
	rootCmd           *cobra.Command
	verbose           bool
	force             bool
	database          string
	keyfile           string
	config            string
	secretsConfigFile string
}

// NewApp factory function follows DIP - Dependency Inversion Principle
func NewApp() App {
	app := &CLIApp{
		rootCmd: &cobra.Command{
			Use:   "secrets",
			Short: "CLI for secrets management",
			Long: `CLI for secrets management with KeePass integration.

Environment Variables:
  SECRETS_YOHNAH_DATABASE_PATH    Path to KeePass database file (.kdbx)
  SECRETS_YOHNAH_KEYFILE_PATH     Path to KeePass keyfile
  SECRETS_YOHNAH_PASSWORD         Password for KeePass database (automation only)

The SECRETS_YOHNAH_PASSWORD environment variable allows for automated
workflows without interactive password prompts.`,
			Version: appVersion,
		},
	}
	
	// Configure version template
	app.rootCmd.SetVersionTemplate(getVersionTemplate())
	
	// OCP - Open/Closed Principle: easy to extend with new commands
	app.setupGlobalFlags()
	app.setupEnvironmentVariables()
	app.setupCommands()
	
	return app
}

// Execute follows SRP - single responsibility of executing commands
func (a *CLIApp) Execute() error {
	return a.rootCmd.Execute()
}

// setupGlobalFlags follows SRP - single responsibility of setting up global flags
func (a *CLIApp) setupGlobalFlags() {
	a.rootCmd.PersistentFlags().BoolVarP(&a.verbose, "verbose", "v", false, "enable verbose output")
	a.rootCmd.PersistentFlags().BoolVarP(&a.force, "force", "f", false, "accept default values for interactive prompts")
	a.rootCmd.PersistentFlags().StringVar(&a.database, "database", "", "path to KeePass database file (.kdbx) (env: SECRETS_YOHNAH_DATABASE_PATH)")
	a.rootCmd.PersistentFlags().StringVar(&a.keyfile, "keyfile", "", "path to KeePass keyfile (env: SECRETS_YOHNAH_KEYFILE_PATH)")
	a.rootCmd.PersistentFlags().StringVarP(&a.config, "config", "c", "", "path to configuration file (env: SECRETS_YOHNAH_CONFIG_PATH)")
	a.rootCmd.PersistentFlags().StringVarP(&a.secretsConfigFile, "secrets-config-file", "s", "", "path to secrets.yml file (env: SECRETS_YOHNAH_SFC_PATH)")
}

// setupEnvironmentVariables follows SRP - single responsibility of setting up environment variables
func (a *CLIApp) setupEnvironmentVariables() {
	// Configure viper to read environment variables
	viper.AutomaticEnv()
	
	// Bind environment variables to viper keys
	viper.BindEnv("database", "SECRETS_YOHNAH_DATABASE_PATH")
	viper.BindEnv("keyfile", "SECRETS_YOHNAH_KEYFILE_PATH")
	viper.BindEnv("password", "SECRETS_YOHNAH_PASSWORD")
	viper.BindEnv("config", "SECRETS_YOHNAH_CONFIG_PATH")
	viper.BindEnv("secrets_config_file", "SECRETS_YOHNAH_SFC_PATH")
}

// IsVerbose follows ISP - provides access to verbose flag state
func (a *CLIApp) IsVerbose() bool {
	return a.verbose
}

// IsForce follows ISP - provides access to force flag state
func (a *CLIApp) IsForce() bool {
	return a.force
}

// GetDatabase follows ISP - provides access to database path
// Precedence: flag > environment variable > config file > empty
func (a *CLIApp) GetDatabase() string {
	// Flag takes precedence over everything
	if a.database != "" {
		return a.database
	}
	// Environment variable takes precedence over config
	if envDB := viper.GetString("database"); envDB != "" {
		return envDB
	}
	// Fall back to config file (will be implemented in init command)
	return ""
}

// GetKeyfile follows ISP - provides access to keyfile path
// Precedence: flag > environment variable > config file > empty
func (a *CLIApp) GetKeyfile() string {
	// Flag takes precedence over everything
	if a.keyfile != "" {
		return a.keyfile
	}
	// Environment variable takes precedence over config
	if envKeyfile := viper.GetString("keyfile"); envKeyfile != "" {
		return envKeyfile
	}
	// Fall back to config file (will be implemented in init command)
	return ""
}

// GetPassword follows ISP - provides access to password from environment only
// No flag available for security reasons - only environment variable
func (a *CLIApp) GetPassword() string {
	return viper.GetString("password")
}

// GetConfig follows ISP - provides access to config file path
// Precedence: flag > environment variable > default (.secrets_yohnah/config.yml)
func (a *CLIApp) GetConfig() string {
	// Flag takes precedence over everything
	if a.config != "" {
		return a.config
	}
	// Environment variable takes precedence over default
	if envConfig := viper.GetString("config"); envConfig != "" {
		return envConfig
	}
	// Default path will be resolved by the caller
	return ""
}

// GetSecretsConfigFile follows ISP - provides access to secrets.yml file path
// Precedence: flag > environment variable > default (./secrets.yml in git root)
func (a *CLIApp) GetSecretsConfigFile() string {
	// Flag takes precedence over everything
	if a.secretsConfigFile != "" {
		return a.secretsConfigFile
	}
	// Environment variable takes precedence over default
	if envSecretsConfig := viper.GetString("secrets_config_file"); envSecretsConfig != "" {
		return envSecretsConfig
	}
	// Default path will be resolved by the caller
	return ""
}

// setupCommands follows SRP - single responsibility of setting up commands
func (a *CLIApp) setupCommands() {
	a.rootCmd.AddCommand(NewInitCommand(a))
	a.rootCmd.AddCommand(a.createShowCommand())
	a.rootCmd.AddCommand(NewSnapshotCommand(a))
}

// getVersionTemplate follows SRP - single responsibility of formatting version output
func getVersionTemplate() string {
	return fmt.Sprintf(`secrets version %s
  commit: %s
  built: %s
  go: %s
`, appVersion, appGitCommit, appBuildTime, runtime.Version())
}