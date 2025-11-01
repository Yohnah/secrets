package main

import (
"fmt"
"os"
"github.com/spf13/cobra"
"github.com/Yohnah/secrets/internal/bdmanager"
"github.com/Yohnah/secrets/internal/configmanager"
"github.com/Yohnah/secrets/internal/inputmanager"
"github.com/Yohnah/secrets/internal/inputmanager/cli"
"github.com/Yohnah/secrets/internal/inputmanager/envvars"
"github.com/Yohnah/secrets/internal/inputmanager/prompts"
"github.com/Yohnah/secrets/internal/inputmanager/readfile"
"github.com/Yohnah/secrets/internal/loggermanager"
"github.com/Yohnah/secrets/internal/logicmanager"
"github.com/Yohnah/secrets/internal/outputmanager"
"github.com/Yohnah/secrets/internal/validatormanager"
)

var (
Version   = "dev"
BuildTime = "unknown"
GitCommit = "unknown"
)

var rootCmd = &cobra.Command{
Use:   "secrets",
Short: "Secrets management tool by Yohnah",
Long:  "A secure secrets management tool that helps developers work with sensitive data.",
}

var initCmd = &cobra.Command{
Use:   "init",
Short: "Initialize the secrets project",
Long:  "Initialize the secrets project in the local environment.",
Run: func(cmd *cobra.Command, args []string) {
logicManager, err := setupManagers(cmd)
if err != nil {
fmt.Fprintf(os.Stderr, "Error: %v\n", err)
os.Exit(1)
}
if err := logicManager.ExecuteInit(); err != nil {
fmt.Fprintf(os.Stderr, "Error: %v\n", err)
os.Exit(1)
}
},
}

var versionCmd = &cobra.Command{
Use:   "version",
Short: "Print version information",
Run: func(cmd *cobra.Command, args []string) {
fmt.Printf("secrets version %s\n", Version)
fmt.Printf("  Build time: %s\n", BuildTime)
fmt.Printf("  Git commit: %s\n", GitCommit)
},
}

func setupManagers(cmd *cobra.Command) (logicmanager.LogicManager, error) {
verbose, _ := cmd.Flags().GetBool("verbose")
logger := loggermanager.NewStderrLogger()
logger.SetVerbose(verbose)
validator := validatormanager.NewStandardValidator(logger)
cliHandler := cli.NewCobraCliReader()
cliHandler.SetCommand(cmd)
envVarsHandler := envvars.NewOsEnvVarsReader()
promptsHandler := prompts.NewStandardPrompts()
fileReader := readfile.NewStandardFileReader()
inputMgr := inputmanager.NewInputManager(cliHandler, envVarsHandler, fileReader, promptsHandler)
config := configmanager.NewStandardConfig(inputMgr, validator, logger)
if err := config.LoadConfig(); err != nil {
return nil, err
}
bd := bdmanager.NewStandardBD(logger, validator)
output := outputmanager.NewStandardOutput(logger)
logicMgr := logicmanager.NewLogicManager(config, bd, output, logger)
return logicMgr, nil
}

func init() {
rootCmd.AddCommand(initCmd)
rootCmd.AddCommand(versionCmd)
rootCmd.PersistentFlags().StringP("config", "c", "", "Config file path")
rootCmd.PersistentFlags().BoolP("verbose", "V", false, "Enable verbose output")
rootCmd.PersistentFlags().BoolP("help", "h", false, "Help for this command")
rootCmd.PersistentFlags().Bool("version", false, "Print version information")
rootCmd.PersistentFlags().Bool("ignore-config-file", false, "Ignore config file")
rootCmd.PersistentFlags().String("database-name", "", "Database name")
rootCmd.PersistentFlags().String("database-path", "", "Database path")
rootCmd.PersistentFlags().String("keyfile", "", "Keyfile path")
rootCmd.PersistentFlags().BoolP("non-interactive", "n", false, "Non-interactive mode")
rootCmd.PersistentFlags().StringP("secrets-file", "f", "", "Secrets.yml file path")
rootCmd.PersistentFlags().StringP("profile", "p", "", "Profile name")
initCmd.Flags().Bool("force-recreate", false, "Force recreate database")
initCmd.Flags().Bool("no-create-database", false, "Do not create database")
initCmd.Flags().Bool("no-keyfile", false, "Do not use keyfile")
}

func main() {
if err := rootCmd.Execute(); err != nil {
fmt.Fprintf(os.Stderr, "Error: %v\n", err)
os.Exit(1)
}
}
