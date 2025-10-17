package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/Yohnah/secrets/internal/template"
	"github.com/Yohnah/secrets/internal/types"
	"github.com/spf13/cobra"
)

var (
	flagMinimal           bool
	flagOutputFormat      string
	flagTreeOutput        string
	flagProfilesOutput    string
	syncedDataFlagProfile string
	syncedDataFlagOutput  string
	variablesFlagOutput   string
	variablesFlagTemplate string
) // showCmd represents the show command
var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show various information",
	Long:  `Display various types of information like templates, status, configuration, etc.`,
}

// showTemplateCmd represents the show template command
var showTemplateCmd = &cobra.Command{
	Use:   "template <template-name>",
	Short: "Show template file",
	Long: `Displays the specified template file with examples and documentation.

Available templates will be listed here.

You can redirect the output to create your own file:
  secrets show template secrets.yml > secrets.yml
  secrets show template k8s.yml > k8s.yml

The template includes:
  - Complete structure with examples
  - Field reference and validation rules
  - Documentation for all field types

Use --minimal flag to get a simplified version without examples.`,
	Args: cobra.ExactArgs(1),
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
	Use:   "tree <environment-name>",
	Short: "Show tree structure of secrets",
	Long: `Display a tree structure of the secrets for a specific profile and environment.

The tree shows:
- Groups and entries hierarchically organized
- Synchronization status indicators:
  ✓ Entry exists in both secrets.yml and database
  ✗ Entry defined in secrets.yml but missing in database
  ⚠ Entry exists in database but not defined in secrets.yml

Profile name can be specified via:
	1. Flag: -p/--profile-name (recommended)
	2. Positional argument (legacy, deprecated)
	3. Auto-detection: if secrets.yml defines a single profile, the CLI selects it automatically

Examples:
  secrets show tree -p webapp-production production
  secrets show tree webapp-production production        # Legacy style
	secrets show tree production                          # Auto-detect single profile
	secrets show tree webapp-production production -o ascii`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runShowTree,
}

// showProfilesCmd represents the show profiles command
var showProfilesCmd = &cobra.Command{
	Use:   "profiles",
	Short: "Show profiles information from secrets.yml",
	Long: `Display information about profiles and their environments defined in secrets.yml.

Shows for each profile:
- Total number of environments
- Environment existence in database (✓/✗)
- Entry count (existing/total entries)

Profile name can be specified via:
  1. Flag: -p/--profile-name (optional, defaults to "all")
  2. Positional argument (legacy, deprecated)

Examples:
  secrets show profiles                    # Show all profiles
  secrets show profiles all                # Show all profiles (explicit)
  secrets show profiles -p webapp-prod     # Show specific profile via flag
  secrets show profiles webapp-prod        # Show specific profile (legacy)
  secrets show profiles -o json            # Output in JSON format`,
	Args: cobra.MaximumNArgs(1),
	RunE: runShowProfiles,
}

// showSyncedDataCmd represents the show synced-data command
var showSyncedDataCmd = &cobra.Command{
	Use:   "synced-data",
	Short: "Show synchronization status between secrets.yml and KeePass database",
	Long: `Check synchronization status between secrets.yml and KeePass database.

Displays for each item:
  - NAME: Item name (environment/item_name)
  - STATUS: ✓ (synced) or ✗ (not synced)
  - ISSUE: "OK" if synced, or describes what's missing (entry/key)
  - FIELD VALUE STATUS: Status of the field value in KeePass
    - "empty": Field exists but has no value
    - "has_data": Field has a value set
    - "N/A": Field does not exist or cannot be checked

Examples:
  # Check sync status (auto-detect profile if single profile)
  secrets show synced-data

  # Check specific profile
  secrets show synced-data --profile-name webapp-production

  # Output in JSON format
  secrets show synced-data -o json

  # Output in YAML format
  secrets show synced-data -o yaml`,
	RunE: runShowSyncedData,
}

// showVariablesCmd represents the show variables command
var showVariablesCmd = &cobra.Command{
	Use:   "variables <environment-name>",
	Short: "Show environment variables for a specific environment",
	Long: `Display environment variables (items with type: envvar) from the specified environment in various formats.

The command filters items of type "envvar" from the environment, retrieves their values from KeePass,
and renders them using the specified output format or custom template.

Available output formats:
  - json (default): JSON format
  - yaml: YAML format
  - dotenv: .env file format
  - k8s: Kubernetes Secret YAML
  - shell.sh, shell.cmd, shell.ps1, etc.: Shell export scripts
  - terraform: Terraform tfvars format
  - spring_boot: Spring Boot properties
  - And many more...

Profile name can be specified via:
  1. Flag: --profile-name (recommended)
  2. Auto-detection: if secrets.yml defines a single profile, it's selected automatically

Examples:
  # Show variables in JSON format (default)
  secrets show variables production

  # Show variables in YAML format
  secrets show variables production --output yaml

  # Show variables as Kubernetes Secret
  secrets show variables production --output k8s

  # Show variables using custom template
  secrets show variables production --template ./my-custom.tpl

  # Show variables for specific profile
  secrets show variables production --profile-name webapp-prod --output dotenv`,
	Args: cobra.ExactArgs(1),
	RunE: runShowVariables,
}

func init() {
	// Register show command with root
	rootCmd.AddCommand(showCmd)

	// Register subcommands with show
	showCmd.AddCommand(showTemplateCmd)
	showCmd.AddCommand(showStatusCmd)
	showCmd.AddCommand(showTreeCmd)
	showCmd.AddCommand(showProfilesCmd)
	showCmd.AddCommand(showSyncedDataCmd)
	showCmd.AddCommand(showVariablesCmd)

	// Flags for template subcommand only
	showTemplateCmd.Flags().BoolVar(&flagMinimal, "minimal", false, "Show minimal template without examples")

	// Flags for status subcommand only
	showStatusCmd.Flags().StringVarP(&flagOutputFormat, "output", "o", "table", "Output format: json, yaml, table")

	// Flags for tree subcommand only
	showTreeCmd.Flags().StringVarP(&flagTreeOutput, "output", "o", "ansi", "Output format: ansi, ascii")

	// Flags for profiles subcommand only
	showProfilesCmd.Flags().StringVarP(&flagProfilesOutput, "output", "o", "table", "Output format: table, json, yaml")

	// Flags for synced-data subcommand only
	showSyncedDataCmd.Flags().StringVarP(&syncedDataFlagProfile, "profile-name", "p", "", "Profile name (optional, auto-detect if single profile)")
	showSyncedDataCmd.Flags().StringVarP(&syncedDataFlagOutput, "output", "o", "table", "Output format: table, json, yaml (default: table)")

	// Flags for variables subcommand only
	showVariablesCmd.Flags().StringVarP(&variablesFlagOutput, "output", "o", "json", "Output format: json, yaml, dotenv, k8s, shell.sh, etc. (default: json)")
	showVariablesCmd.Flags().StringVarP(&variablesFlagTemplate, "template", "t", "", "Path to custom template file (overrides --output)")

	// Update show template help with available templates
	updateShowTemplateHelp()
}

func updateShowTemplateHelp() {
	templates, err := template.GetAvailableTemplatesWithDescriptions()
	if err != nil {
		// Fallback to static help if we can't get templates
		return
	}

	var templateList strings.Builder
	templateList.WriteString("Available templates:\n")
	for name, description := range templates {
		templateList.WriteString(fmt.Sprintf("  - %s: %s\n", name, description))
	}

	showTemplateCmd.Long = fmt.Sprintf(`Displays the specified template file with examples and documentation.

%s
You can redirect the output to create your own file:
  secrets show template secrets.yml > secrets.yml
  secrets show template k8s.yml > k8s.yml

The template includes:
  - Complete structure with examples
  - Field reference and validation rules
  - Documentation for all field types

Use --minimal flag to get a simplified version without examples.`, templateList.String())
}

func runShowTemplate(cmd *cobra.Command, args []string) error {
	// Extract template name from arguments
	templateName := args[0]

	// CliMgr captures ALL command-specific flags and feeds them to ConfigMgr
	commandFlags := &types.CommandFlags{
		Minimal:      flagMinimal,
		TemplateName: templateName,
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

	// Determine profile name from flag or positional argument
	var profileName, environmentName string

	switch {
	case flagProfileName != "":
		// Priority 1: Use flag if provided
		profileName = flagProfileName
		if len(args) < 1 {
			managers.Logger.Error("environment name is required")
			os.Exit(1)
		}
		environmentName = args[0]
	case len(args) == 2:
		// Priority 2: Legacy positional arguments (backward compatibility)
		profileName = args[0]
		environmentName = args[1]
	case len(args) == 1:
		// Auto-detection path: only environment provided
		environmentName = args[0]
	default:
		managers.Logger.Error("environment name is required")
		os.Exit(1)
	}

	// Execute business logic (delegate all decisions to CORE)
	// SecretsManager will pull processed config from ConfigMgr
	if err := managers.Secrets.ShowTree(profileName, environmentName, flagTreeOutput); err != nil {
		managers.Logger.Error(err.Error())
		os.Exit(1)
	}

	return nil
}

func runShowProfiles(cmd *cobra.Command, args []string) error {
	// CliMgr captures ALL command-specific flags and feeds them to ConfigMgr
	commandFlags := &types.CommandFlags{
		OutputFormat: flagProfilesOutput,
	}

	// Create manager context with captured flags
	managers := NewManagerContext(commandFlags)

	// Determine profile name from flag or positional argument
	var profileFilter string

	if flagProfileName != "" {
		// Priority 1: Use flag if provided
		profileFilter = flagProfileName
	} else if len(args) > 0 {
		// Priority 2: Legacy positional argument (backward compatibility)
		profileFilter = args[0]
	} else {
		// Default: show all profiles
		profileFilter = "all"
	}

	// Execute business logic (delegate all decisions to CORE)
	// SecretsManager will pull processed config from ConfigMgr
	if err := managers.Secrets.ShowProfiles(profileFilter); err != nil {
		managers.Logger.Error(err.Error())
		os.Exit(1)
	}

	return nil
}

func runShowSyncedData(cmd *cobra.Command, args []string) error {
	// CliMgr captures ALL command-specific flags and feeds them to ConfigMgr
	commandFlags := &types.CommandFlags{
		OutputFormat: syncedDataFlagOutput,
	}

	// Create manager context with captured flags
	managers := NewManagerContext(commandFlags)

	// Execute business logic (delegate all decisions to CORE)
	if err := managers.Secrets.ShowSyncedData(syncedDataFlagProfile); err != nil {
		managers.Logger.Error(err.Error())
		os.Exit(1)
	}

	return nil
}

func runShowVariables(cmd *cobra.Command, args []string) error {
	// Extract environment name from arguments
	environmentName := args[0]

	// Validate output format (reject "secrets.yml")
	if variablesFlagOutput == "secrets.yml" {
		fmt.Fprintln(os.Stderr, "Error: 'secrets.yml' is not a valid output format for variables")
		os.Exit(1)
	}

	// Read custom template content if specified
	var customTemplateContent string
	if variablesFlagTemplate != "" {
		content, err := os.ReadFile(variablesFlagTemplate)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Error: Template file not found: %s\n", variablesFlagTemplate)
			} else {
				fmt.Fprintf(os.Stderr, "Error: Failed to read template file '%s': %v\n", variablesFlagTemplate, err)
			}
			os.Exit(1)
		}
		customTemplateContent = string(content)
	}

	// CliMgr captures ALL command-specific flags and feeds them to ConfigMgr
	commandFlags := &types.CommandFlags{
		OutputFormat: variablesFlagOutput,
	}

	// Create manager context with captured flags
	managers := NewManagerContext(commandFlags)

	// Execute business logic (delegate all decisions to CORE)
	// SecretsManager will pull processed config from ConfigMgr
	if err := managers.Secrets.ShowVariables(environmentName, variablesFlagOutput, customTemplateContent); err != nil {
		managers.Logger.Error(err.Error())
		os.Exit(1)
	}

	return nil
}
