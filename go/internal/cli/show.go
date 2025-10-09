package cli

import (
	"os"

	"github.com/Yohnah/secrets/internal/types"
	"github.com/spf13/cobra"
)

var (
	flagMinimal        bool
	flagOutputFormat   string
	flagTreeOutput     string
	flagProfilesOutput string
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

func init() {
	// Register show command with root
	rootCmd.AddCommand(showCmd)

	// Register subcommands with show
	showCmd.AddCommand(showTemplateCmd)
	showCmd.AddCommand(showStatusCmd)
	showCmd.AddCommand(showTreeCmd)
	showCmd.AddCommand(showProfilesCmd)

	// Flags for template subcommand only
	showTemplateCmd.Flags().BoolVar(&flagMinimal, "minimal", false, "Show minimal template without examples")

	// Flags for status subcommand only
	showStatusCmd.Flags().StringVarP(&flagOutputFormat, "output", "o", "table", "Output format: json, yaml, table")

	// Flags for tree subcommand only
	showTreeCmd.Flags().StringVarP(&flagTreeOutput, "output", "o", "ansi", "Output format: ansi, ascii")

	// Flags for profiles subcommand only
	showProfilesCmd.Flags().StringVarP(&flagProfilesOutput, "output", "o", "table", "Output format: table, json, yaml")
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
