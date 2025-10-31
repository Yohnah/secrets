package main

import (
	"fmt"
	"os"

	"github.com/Yohnah/secrets/internal/bdmanager"
	"github.com/Yohnah/secrets/internal/configmanager"
	"github.com/Yohnah/secrets/internal/inputmanager/cli"
	"github.com/Yohnah/secrets/internal/inputmanager/envvars"
	"github.com/Yohnah/secrets/internal/loggermanager"
	"github.com/Yohnah/secrets/internal/logicmanager"
	"github.com/Yohnah/secrets/internal/outputmanager"
	"github.com/Yohnah/secrets/internal/validatormanager"
	"github.com/spf13/cobra"
)

var (
	// Version info (injected by ldflags during build)
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	// Create infrastructure components
	logger := loggermanager.NewStderrLogger()
	validator := validatormanager.NewStandardValidator(logger)
	cliReader := cli.NewCobraCliReader()
	envReader := envvars.NewOsEnvVarsReader()

	// Create root command
	rootCmd := &cobra.Command{
		Use:   "secrets",
		Short: "Secrets - Secure secrets management tool",
		Long:  "Secrets helps developers manage secrets securely from a KeePass database",
	}

	// Add persistent flags (global)
	rootCmd.PersistentFlags().StringP("config", "c", "", "Config file path")
	rootCmd.PersistentFlags().BoolP("verbose", "V", false, "Verbose output")
	rootCmd.PersistentFlags().Bool("ignore-config-file", false, "Ignore config file")
	rootCmd.PersistentFlags().String("database-name", "", "Database name")
	rootCmd.PersistentFlags().String("database-path", "", "Database path")
	rootCmd.PersistentFlags().String("keyfile", "", "Keyfile path")
	rootCmd.PersistentFlags().BoolP("non-interactive", "n", false, "Non-interactive mode")
	rootCmd.PersistentFlags().StringP("secrets-file", "f", "", "Secrets.yml path")

	// Add version command
	rootCmd.Version = fmt.Sprintf("%s (commit: %s, built: %s)", Version, GitCommit, BuildTime)

	// Add init command
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize secrets project",
		Long:  "Initialize secrets project in local environment",
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeInitCommand(cmd, cliReader, envReader, validator, logger)
		},
	}

	// Add local flags for init command
	initCmd.Flags().Bool("force-recreate", false, "Force recreate database if exists")
	initCmd.Flags().Bool("no-create-database", false, "Do not create database")
	initCmd.Flags().Bool("no-keyfile", false, "Do not use keyfile")

	rootCmd.AddCommand(initCmd)

	// Execute
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func executeInitCommand(
	cmd *cobra.Command,
	cliReader cli.CliReader,
	envReader envvars.EnvVarsReader,
	validator validatormanager.Validator,
	logger loggermanager.Logger,
) error {
	// Set command for CLI reader
	cliReader.SetCommand(cmd)

	// Create config manager
	config := configmanager.NewStandardConfig(cliReader, envReader, validator, logger)

	// Load configuration
	if err := config.LoadConfig(); err != nil {
		return err
	}

	// Create output manager
	output := outputmanager.NewStandardOutput(logger)

	// Create BD manager
	bd := bdmanager.NewStandardBD(logger, validator)

	// Create logic manager
	logic := logicmanager.NewStandardLogic(config, logger, validator, cliReader, envReader, output, bd)

	// Execute init workflow
	return logic.ExecuteInit()
}
