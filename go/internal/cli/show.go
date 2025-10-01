package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// createShowCommand follows SRP - single responsibility of creating the show command
func (a *CLIApp) createShowCommand() *cobra.Command {
	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show various information and templates",
		Long: `Show various information and templates for secrets management.

Available subcommands:
  template    Show a template for secrets.yml configuration file`,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	// Add subcommands
	showCmd.AddCommand(a.createShowTemplateCommand())

	return showCmd
}

// createShowTemplateCommand follows SRP - single responsibility of creating the template subcommand
func (a *CLIApp) createShowTemplateCommand() *cobra.Command {
	templateCmd := &cobra.Command{
		Use:   "template",
		Short: "Show a template for secrets.yml configuration file",
		Long: `Show a template for secrets.yml configuration file.

This command outputs a basic template that you can use to create your own secrets.yml file.
You can redirect the output to create a new file:

  secrets show template > secrets.yml
  secrets show template --minimal > secrets.yml

The template includes examples of:
  - Metadata section with profile and default environment
  - Environment configurations with various secret types
  - Different types of secrets (envvar, ssh_agent)
  - Entry paths with and without subgroups
  - Proper YAML formatting and structure

Use --minimal flag to output only the essential template without commented examples.`,
		Run: func(cmd *cobra.Command, args []string) {
			a.runShowTemplate(cmd, args)
		},
	}

	// Add flags
	templateCmd.Flags().Bool("minimal", false, "show minimal template without commented examples")

	return templateCmd
}

// runShowTemplate follows SRP - single responsibility of executing the template command
func (a *CLIApp) runShowTemplate(cmd *cobra.Command, args []string) {
	template := `metadata:
  profile: "profile_name"
  default_environment: "environment_name"
---
environment_name:
  - name: DATABASE_URL
    entry: "/path/to/entry/in/database"
    key: "entry field name"
    type: "(envvar|ssh_agent)"

#example of multiple environments and secret types
#development:
#  - name: DATABASE_URL
#    entry: "/databases/main"
#    key: "connection_string"
#    type: "envvar"
#  - name: API_KEY
#    entry: "/api_keys"
#    key: "token"
#    type: "envvar"
#  - name: SSH_PRIVATE_KEY
#    entry: "/ssh_keys/deploy"
#    key: "attachments/private_key"
#    type: "ssh_agent"
#  - name: ENCRYPTION_KEY
#    entry: "/encryption"
#    key: "master_key"
#    type: "envvar"
#
#production:
#  - name: DATABASE_URL
#    entry: "/databases/main"
#    key: "connection_string"
#    type: "envvar"
#  - name: API_KEY
#    entry: "/api_keys"
#    key: "token"
#    type: "envvar"
#  - name: SSH_PRIVATE_KEY
#    entry: "/ssh_keys/deploy"
#    key: "attachments/github_key"
#    type: "ssh_agent"
#  - name: ENCRYPTION_KEY
#    entry: "/encryption"
#    key: "master_key"
#    type: "envvar"
`

	// Check if minimal flag is set
	minimal, _ := cmd.Flags().GetBool("minimal")
	if minimal {
		// Filter out commented lines
		lines := strings.Split(template, "\n")
		var filteredLines []string
		for _, line := range lines {
			// Keep lines that don't start with # (ignoring whitespace)
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "#") {
				filteredLines = append(filteredLines, line)
			}
		}
		template = strings.Join(filteredLines, "\n")
		// Clean up multiple consecutive empty lines
		template = strings.ReplaceAll(template, "\n\n\n", "\n\n")
	}

	fmt.Print(template)
}