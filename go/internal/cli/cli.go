package cli

import (
	"fmt"
	"os"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CLIApp represents the minimalist CLI application
type CLIApp struct {
	rootCmd      *cobra.Command
	verbose      bool
	force        bool
	database     string
	keyfile      string
}

// NewCLIApp creates CLI according to project specifications
func NewCLIApp() *CLIApp {
	app := &CLIApp{}
	app.rootCmd = &cobra.Command{
		Use:     "secrets",
		Short:   "CLI for completed SOLID system",
		Version: "1.0.0",
	}
	app.setupFlags()
	app.setupCommands()
	
	// Initialize viper to read configuration
	viper.AutomaticEnv()
	
	return app
}

func (a *CLIApp) setupFlags() {
	a.rootCmd.PersistentFlags().BoolVarP(&a.verbose, "verbose", "v", false, "enable verbose output")
	a.rootCmd.PersistentFlags().BoolVarP(&a.force, "force", "f", false, "accept default values for interactive prompts")
	
	// Setup database flag with default value and dynamic description
	defaultDbPath := ".secrets_yohnah/secrets.kdbx"
	databaseDesc := a.BuildFlagDescription("path to KeePass database file", "SECRETS_YOHNAH_DATABASE_PATH")
	a.rootCmd.PersistentFlags().StringVar(&a.database, "database", defaultDbPath, databaseDesc)
	
	// Setup keyfile flag with default value and dynamic description
	defaultKeyPath := ".secrets_yohnah/secrets.key"
	keyfileDesc := a.BuildFlagDescription("path to KeePass keyfile", "SECRETS_YOHNAH_KEYFILE_PATH")
	a.rootCmd.PersistentFlags().StringVar(&a.keyfile, "keyfile", defaultKeyPath, keyfileDesc)
	
	viper.BindPFlag("verbose", a.rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("force", a.rootCmd.PersistentFlags().Lookup("force"))
	viper.BindPFlag("database", a.rootCmd.PersistentFlags().Lookup("database"))
	viper.BindPFlag("keyfile", a.rootCmd.PersistentFlags().Lookup("keyfile"))
	
	// Bind environment variables
	viper.BindEnv("database", "SECRETS_YOHNAH_DATABASE_PATH")
	viper.BindEnv("keyfile", "SECRETS_YOHNAH_KEYFILE_PATH")
}

func (a *CLIApp) setupCommands() {
	// Add init command
	a.rootCmd.AddCommand(NewInitCommand(a))
}

func (a *CLIApp) Execute() error {
return a.rootCmd.Execute()
}

func (a *CLIApp) AddCommand(cmd *cobra.Command) {
	a.rootCmd.AddCommand(cmd)
}

// IsVerbose returns the verbose flag state
func (a *CLIApp) IsVerbose() bool {
	return a.verbose
}

// IsForce returns the force flag state
func (a *CLIApp) IsForce() bool {
	return a.force
}

// GetDatabase returns the database path from flag or environment variable
func (a *CLIApp) GetDatabase() string {
	return viper.GetString("database")
}

// GetKeyfile returns the keyfile path from flag or environment variable
func (a *CLIApp) GetKeyfile() string {
	return viper.GetString("keyfile")
}

// UsingExternalPaths returns true if database or keyfile flags/env vars are used (not defaults)
func (a *CLIApp) UsingExternalPaths() bool {
	dbPath := a.GetDatabase()
	keyPath := a.GetKeyfile()
	
	// Check if using non-default paths
	defaultDbPath := ".secrets_yohnah/secrets.kdbx"
	defaultKeyPath := ".secrets_yohnah/secrets.key"
	
	return (dbPath != "" && dbPath != defaultDbPath) || (keyPath != "" && keyPath != defaultKeyPath)
}

// BuildFlagDescription creates a dynamic flag description including env var values
func (a *CLIApp) BuildFlagDescription(baseDesc, envVarName string) string {
	desc := baseDesc
	envValue := os.Getenv(envVarName)
	
	if envValue != "" {
		desc += fmt.Sprintf(" (env: %s='%s')", envVarName, envValue)
	} else {
		desc += fmt.Sprintf(" (env: %s)", envVarName)
	}
	
	return desc
}