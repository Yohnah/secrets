package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	// Import variables command flags
	flagDecodeBase64 bool
)

// importCmd represents the import command
var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import data into KeePass database",
	Long: `Import data from various file formats into the KeePass database.

The import command supports multiple subcommands for different types of data:
  - variables: Import environment variables from configuration files

Examples:
  # Import variables from a single file
  secrets import variables production /path/to/.env

  # Import variables from multiple files using glob pattern
  secrets import variables production /path/to/*.env

  # Import with base64 decoding (useful for Kubernetes secrets)
  secrets import variables production k8s-secrets.yml --decode-base64

  # Import to a specific profile
  secrets import variables production .env --profile-name myapp`,
}

// importVariablesCmd represents the import variables command
var importVariablesCmd = &cobra.Command{
	Use:   "variables <environment-name> <file-path-or-pattern>...",
	Short: "Import variables from files into KeePass database",
	Long: `Import environment variables from various file formats into the KeePass database.

Supported formats (detected by file extension):
  - .env, .dotenv: Environment variable files (KEY=value or KEY="value")
  - .json: JSON files with key-value pairs
  - .yml, .yaml: YAML files (plain or Kubernetes secrets)
  - .properties: Java properties files
  - .toml: TOML configuration files
  - .tfvars: Terraform variables files
  - .ini: INI configuration files

The command matches variable names from the file with items defined in secrets.yml.
Only variables with matching names in secrets.yml will be imported. Variables not
found in secrets.yml are silently ignored.

If the item's key is "attachments/filename.ext", the variable's value will be
stored as an attachment with the specified filename.

Behavior:
  - Multiple files can be specified as separate arguments
  - Glob patterns are supported (e.g., *.env) - expanded by shell or internally
  - If multiple files contain the same variable, the last value wins
  - Existing values in the database are replaced
  - Variables not found in secrets.yml are ignored (no error)

Examples:
  # Import from a single .env file
  secrets import variables production .env

  # Import from multiple files (shell expansion)
  secrets import variables production ./.trash/*.yml

  # Import from multiple files (explicit)
  secrets import variables production file1.env file2.env file3.json

  # Import Kubernetes secrets with base64 decoding
  secrets import variables production k8s-secret.yml --decode-base64

  # Import to specific profile
  secrets import variables staging .env --profile-name myapp-staging`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		environmentName := args[0]
		filePatterns := args[1:]

		// Expand glob patterns and collect all files
		var allFiles []string
		for _, pattern := range filePatterns {
			// Try glob expansion
			files, err := filepath.Glob(pattern)
			if err != nil {
				return fmt.Errorf("invalid file pattern '%s': %w", pattern, err)
			}

			// If glob found files, use them; otherwise use pattern as-is (direct file path)
			if len(files) > 0 {
				allFiles = append(allFiles, files...)
			} else {
				allFiles = append(allFiles, pattern)
			}
		}

		if len(allFiles) == 0 {
			return fmt.Errorf("no files found")
		}

		// Get managers
		managers := NewManagerContext(nil)

		// Execute import
		if err := managers.Secrets.ImportVariables(environmentName, allFiles, flagDecodeBase64); err != nil {
			return err
		}

		return nil
	},
}

func init() {
	// Add import command to root
	rootCmd.AddCommand(importCmd)

	// Add variables subcommand to import
	importCmd.AddCommand(importVariablesCmd)

	// Add flags to import variables command
	importVariablesCmd.Flags().BoolVar(&flagDecodeBase64, "decode-base64", false, "Decode base64-encoded values before storing (useful for Kubernetes secrets)")
}
