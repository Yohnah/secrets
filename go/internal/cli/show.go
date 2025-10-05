package cli

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	flagMinimal      bool
	flagOutputFormat string
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

func init() {
	// Register show command with root
	rootCmd.AddCommand(showCmd)

	// Register subcommands with show
	showCmd.AddCommand(showTemplateCmd)
	showCmd.AddCommand(showStatusCmd)

	// Flags for template subcommand only
	showTemplateCmd.Flags().BoolVar(&flagMinimal, "minimal", false, "Show minimal template without examples")

	// Flags for status subcommand only
	showStatusCmd.Flags().StringVarP(&flagOutputFormat, "output", "o", "table", "Output format: json, yaml, table")
}

func runShowTemplate(cmd *cobra.Command, args []string) error {
	// Create manager context with standard setup
	managers := NewManagerContext()

	// Execute business logic (delegate all decisions to CORE)
	if err := managers.Secrets.ShowTemplate(flagMinimal); err != nil {
		managers.Logger.Error(err.Error())
		os.Exit(1)
	}

	return nil
}

func runShowStatus(cmd *cobra.Command, args []string) error {
	// Create manager context with standard setup
	managers := NewManagerContext()

	// Pass output format to SecretsManager
	// SecretsManager structures data and delegates formatting to OutputManager
	if err := managers.Secrets.Status(flagOutputFormat); err != nil {
		managers.Logger.Error(err.Error())
		os.Exit(1)
	}

	return nil
}
