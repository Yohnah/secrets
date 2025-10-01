package cli

import (
	"fmt"

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

The template includes examples of:
  - Metadata section with profile and default environment
  - Environment configurations with various secret types
  - Different types of secrets (envvar, ssh_agent)
  - Entry paths with and without subgroups
  - Proper YAML formatting and structure`,
		Run: func(cmd *cobra.Command, args []string) {
			a.runShowTemplate(cmd, args)
		},
	}

	return templateCmd
}

// runShowTemplate follows SRP - single responsibility of executing the template command
func (a *CLIApp) runShowTemplate(cmd *cobra.Command, args []string) {
	template := `metadata:
  profile: "my-project"
  default_environment: "development"
---
development:
  - name: DATABASE_URL
    entry: "/databases/development/main"
    key: "connection_string"
    type: "envvar"
  - name: API_KEY
    entry: "/api_keys"
    key: "token"
    type: "envvar"
  - name: SSH_PRIVATE_KEY
    entry: "/ssh_keys/development/deploy"
    key: "attachments/private_key"
    type: "ssh_agent"
  - name: ENCRYPTION_KEY
    entry: "/encryption"
    key: "master_key"
    type: "envvar"

staging:
  - name: DATABASE_URL
    entry: "/databases/staging/main"
    key: "connection_string"
    type: "envvar"
  - name: API_KEY
    entry: "/api_keys"
    key: "token"
    type: "envvar"
  - name: SSH_PRIVATE_KEY
    entry: "/ssh_keys/staging/deploy"
    key: "private_key"
    type: "ssh_agent"

production:
  - name: DATABASE_URL
    entry: "/databases/production/main"
    key: "connection_string"
    type: "envvar"
  - name: API_KEY
    entry: "/api_keys"
    key: "token"
    type: "envvar"
  - name: SSH_PRIVATE_KEY
    entry: "/ssh_keys/production/deploy"
    key: "private_key"
    type: "ssh_agent"
  - name: ENCRYPTION_KEY
    entry: "/encryption"
    key: "master_key"
    type: "envvar"
  - name: GITHUB_SSH_KEY
    entry: "/ssh_keys/github"
    key: "attachments/github_key"
    type: "ssh_agent"
  - name: DOCKER_REGISTRY_TOKEN
    entry: "/docker/registry"
    key: "access_token"
    type: "envvar"
`

	fmt.Print(template)
}