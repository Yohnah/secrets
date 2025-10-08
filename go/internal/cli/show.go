package cli

import (
	"os"

	"github.com/Yohnah/secrets/internal/types"
	"github.com/spf13/cobra"
)

var (
	flagMinimal      bool
	flagOutputFormat string
	flagTreeOutput   string
) // showCmd represents the show command
var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show various information",
	Long:  `Display various types of information like templates, status, configuration, etc.`,
}

// showTemplateCmd represents the show template command
var showTemplateCmd = &cobra.Command{
	Use:   "template",
	Short: "Show secrets.yml template",
	Long: `Displays the secrets.yml template file with examples and documentation.

You can redirect the output to create your own secrets.yml:
  secrets show template > secrets.yml

The template includes:
  - Complete structure with metadata, environments, and outputs sections
  - Examples for different profiles (production, development, CI/CD)
  - Field reference and validation rules
  - Documentation for all field types`,
	RunE: runShowTemplate,
}

// showStatusCmd represents the show status command
var showStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show status of secrets database",
	Long: `Show the current status of the secrets database including:
- Database location and accessibility
- Keyfile location
- Last modification time
- Configuration file status`,
	RunE: runShowStatus,
}

// showTreeCmd represents the show tree command
var showTreeCmd = &cobra.Command{
	Use:   "tree <profile-name> <environment-name>",
	Short: "Show tree structure of secrets",
	Long: `Display a tree structure of the secrets for a specific profile and environment.

The tree shows:
- Groups and entries hierarchically organized
- Synchronization status indicators:
  ✓ Entry exists in both secrets.yml and database
  ✗ Entry defined in secrets.yml but missing in database
  ⚠ Entry exists in database but not defined in secrets.yml

Example:
  secrets show tree webapp-production production
  secrets show tree webapp-production production -o ascii`,
	Args: cobra.ExactArgs(2),
	RunE: runShowTree,
}

func init() {
	// Register show command with root
	rootCmd.AddCommand(showCmd)

	// Register subcommands with show
	showCmd.AddCommand(showTemplateCmd)
	showCmd.AddCommand(showStatusCmd)
	showCmd.AddCommand(showTreeCmd)

	// Flags for template subcommand only
	showTemplateCmd.Flags().BoolVar(&flagMinimal, "minimal", false, "Show minimal template without examples")

	// Flags for status subcommand only
	showStatusCmd.Flags().StringVarP(&flagOutputFormat, "output", "o", "table", "Output format: json, yaml, table")

	// Flags for tree subcommand only
	showTreeCmd.Flags().StringVarP(&flagTreeOutput, "output", "o", "ansi", "Output format: ansi, ascii")
}

func runShowTemplate(cmd *cobra.Command, args []string) error {
	// CliMgr captures ALL command-specific flags and feeds them to ConfigMgr
	commandFlags := &types.CommandFlags{
		Minimal: flagMinimal,
	}

	// Create manager context with captured flags
	managers := NewManagerContext(commandFlags)

	// Execute business logic (delegate all decisions to CORE)
	// SecretsManager will pull processed config from ConfigMgr
	if err := managers.Secrets.ShowTemplate(); err != nil {
		managers.Logger.Error(err.Error())
		os.Exit(1)
	}

	return nil
}

func runShowStatus(cmd *cobra.Command, args []string) error {
	// CliMgr captures ALL command-specific flags and feeds them to ConfigMgr
	commandFlags := &types.CommandFlags{
		OutputFormat: flagOutputFormat,
	}

	// Create manager context with captured flags
	managers := NewManagerContext(commandFlags)

	// Execute business logic (delegate all decisions to CORE)
	// SecretsManager will pull processed config from ConfigMgr
	if err := managers.Secrets.Status(); err != nil {
		managers.Logger.Error(err.Error())
		os.Exit(1)
	}

	return nil
}

func runShowTree(cmd *cobra.Command, args []string) error {
	// CliMgr captures ALL command-specific flags and feeds them to ConfigMgr
	commandFlags := &types.CommandFlags{
		OutputFormat: flagTreeOutput,
	}

	// Create manager context with captured flags
	managers := NewManagerContext(commandFlags)

	// Execute business logic (delegate all decisions to CORE)
	// SecretsManager will pull processed config from ConfigMgr
	profileName := args[0]
	environmentName := args[1]

	if err := managers.Secrets.ShowTree(profileName, environmentName, flagTreeOutput); err != nil {
		managers.Logger.Error(err.Error())
		os.Exit(1)
	}

	return nil
}
