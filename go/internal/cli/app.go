package cli

import (
	"fmt"
	"runtime"
	
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/git"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/prompt"
)

// GlobalFlags holds all global flags for the CLI
// Follows SRP - Single Responsibility for global configuration
type GlobalFlags struct {
	ConfigPath           string
	DatabasePath         string
	KeyfilePath          string
	SecretsConfigPath    string
	Verbose              bool
	Force                bool
	IgnoreGitRepository  bool
}

// CLIApp represents the main CLI application
// Follows SRP - Single Responsibility Principle: manages CLI application state
type CLIApp struct {
	rootCmd     *cobra.Command
	globalFlags GlobalFlags
	
	// Version information
	version   string
	buildTime string
	gitCommit string
}

// NewCLIApp creates a new CLI application instance
// Follows DIP - Dependency Inversion Principle: factory function
func NewCLIApp(version, buildTime, gitCommit string) *CLIApp {
	app := &CLIApp{
		version:   version,
		buildTime: buildTime,
		gitCommit: gitCommit,
	}
	
	app.setupRootCommand()
	app.setupGlobalFlags()
	app.setupEnvironmentVariables()
	app.addCommands()
	
	return app
}

// setupRootCommand configures the root cobra command
func (a *CLIApp) setupRootCommand() {
	a.rootCmd = &cobra.Command{
		Use:   "secrets",
		Short: "Secrets CLI - A secure secrets management tool with KeePass integration",
		Long: `Secrets CLI - A secure secrets management tool with KeePass integration

This tool helps you manage secrets across different environments using KeePass databases.
It supports versioning, snapshots, and multiple environments with a simple YAML configuration.

Environment Variables:
  SECRETS_YOHNAH_PASSWORD       Password for KeePass database (avoids interactive prompt)
  SECRETS_YOHNAH_DATABASE_PATH  Path to KeePass database file (.kdbx)
  SECRETS_YOHNAH_KEYFILE_PATH   Path to KeePass keyfile
  SECRETS_YOHNAH_CONFIG_PATH    Path to configuration file
  SECRETS_YOHNAH_SFC_PATH       Path to secrets.yml file

The SECRETS_YOHNAH_PASSWORD environment variable allows for automated
scripts and CI/CD pipelines to work without interactive password prompts.

Examples:
  secrets init                           # Initialize new project
  secrets show template                  # Generate secrets.yml template
  secrets snapshot new                   # Create new snapshot
  secrets snapshot list                  # List all snapshots
  secrets --version                      # Show version information`,
		Version: a.version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Update global flags from cobra after parsing
			a.updateGlobalFlagsFromCommand(cmd)
		},
	}
	
	// Configure custom version template
	a.rootCmd.SetVersionTemplate(a.getVersionTemplate())
}

// setupGlobalFlags configures global flags for all commands
func (a *CLIApp) setupGlobalFlags() {
	flags := a.rootCmd.PersistentFlags()
	
	// Global flags - applies to all commands
	flags.StringVarP(&a.globalFlags.ConfigPath, "config", "c", "", "path to configuration file (env: SECRETS_YOHNAH_CONFIG_PATH)")
	flags.StringVar(&a.globalFlags.DatabasePath, "database", "", "path to KeePass database file (.kdbx) (env: SECRETS_YOHNAH_DATABASE_PATH)")
	flags.StringVar(&a.globalFlags.KeyfilePath, "keyfile", "", "path to KeePass keyfile (env: SECRETS_YOHNAH_KEYFILE_PATH)")
	flags.StringVarP(&a.globalFlags.SecretsConfigPath, "secrets-config-file", "s", "", "path to secrets.yml file (env: SECRETS_YOHNAH_SFC_PATH)")
	flags.BoolVarP(&a.globalFlags.Verbose, "verbose", "v", false, "enable verbose output")
	flags.BoolVarP(&a.globalFlags.Force, "force", "f", false, "force operation without confirmation")
	flags.BoolVar(&a.globalFlags.IgnoreGitRepository, "ignore-git-repository", false, "ignore git repository requirement and use current directory")
}

// setupEnvironmentVariables follows SRP - single responsibility of setting up environment variables
func (a *CLIApp) setupEnvironmentVariables() {
	// Configure viper to read environment variables
	viper.AutomaticEnv()
	
	// Bind environment variables to viper keys
	viper.BindEnv("database", "SECRETS_YOHNAH_DATABASE_PATH")
	viper.BindEnv("keyfile", "SECRETS_YOHNAH_KEYFILE_PATH")
	viper.BindEnv("config", "SECRETS_YOHNAH_CONFIG_PATH")
	viper.BindEnv("secrets-config-file", "SECRETS_YOHNAH_SFC_PATH")
	viper.BindEnv("password", "SECRETS_YOHNAH_PASSWORD")
}

// updateGlobalFlagsFromCommand updates global flags with values from environment or flags
func (a *CLIApp) updateGlobalFlagsFromCommand(cmd *cobra.Command) {
	// Override with environment variables if flags are empty
	if a.globalFlags.DatabasePath == "" {
		a.globalFlags.DatabasePath = viper.GetString("database")
	}
	if a.globalFlags.KeyfilePath == "" {
		a.globalFlags.KeyfilePath = viper.GetString("keyfile")
	}
	if a.globalFlags.ConfigPath == "" {
		a.globalFlags.ConfigPath = viper.GetString("config")
	}
	if a.globalFlags.SecretsConfigPath == "" {
		a.globalFlags.SecretsConfigPath = viper.GetString("secrets-config-file")
	}
}

// addCommands adds all subcommands to the root command
// Follows SRP - Single Responsibility Principle: only handles command registration
func (a *CLIApp) addCommands() {
	// Create dependencies for commands
	log := logger.New(a.globalFlags.Verbose)
	configManager := config.NewManager(log)
	gitFinder := git.NewRootFinder(log)
	keepassManager := keepass.NewManager(log)
	prompter := prompt.NewInteractivePrompter(log)
	
	// Add init command with dependencies
	a.rootCmd.AddCommand(NewInitCommand(
		log,
		configManager,
		gitFinder,
		keepassManager,
		prompter,
		&a.globalFlags,
	))
}

// Execute runs the CLI application
func (a *CLIApp) Execute() error {
	return a.rootCmd.Execute()
}

// GetGlobalFlags returns the current global flags
func (a *CLIApp) GetGlobalFlags() GlobalFlags {
	return GlobalFlags{
		ConfigPath:          a.globalFlags.ConfigPath,
		DatabasePath:        a.globalFlags.DatabasePath,
		KeyfilePath:         a.globalFlags.KeyfilePath,
		SecretsConfigPath:   a.globalFlags.SecretsConfigPath,
		Verbose:             a.globalFlags.Verbose,
		Force:               a.globalFlags.Force,
		IgnoreGitRepository: a.globalFlags.IgnoreGitRepository,
	}
}

// Getter methods for accessing global state
// Follows ISP - Interface Segregation Principle: expose only needed methods

func (a *CLIApp) IsVerbose() bool {
	return a.globalFlags.Verbose
}

func (a *CLIApp) IsForce() bool {
	return a.globalFlags.Force
}

func (a *CLIApp) GetConfig() string {
	return a.globalFlags.ConfigPath
}

func (a *CLIApp) GetDatabase() string {
	return a.globalFlags.DatabasePath
}

func (a *CLIApp) GetKeyfile() string {
	return a.globalFlags.KeyfilePath
}

func (a *CLIApp) GetSecretsConfigFile() string {
	return a.globalFlags.SecretsConfigPath
}

func (a *CLIApp) GetVersion() string {
	return a.version
}

func (a *CLIApp) GetBuildTime() string {
	return a.buildTime
}

func (a *CLIApp) GetGitCommit() string {
	return a.gitCommit
}

// getVersionTemplate follows SRP - single responsibility of formatting version output
// Returns detailed version information including commit, build time, and Go version
func (a *CLIApp) getVersionTemplate() string {
	return fmt.Sprintf(`secrets version %s
  commit: %s
  built: %s
  go: %s
`, a.version, a.gitCommit, a.buildTime, runtime.Version())
}