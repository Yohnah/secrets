package cli

import (
	_ "embed"
	"strings"

	"github.com/spf13/cobra"
)

// Embed the official template file into the binary
//
//go:embed templates/secrets.tpl.yml
var showTemplateContent string

// NewShowCommand creates the show command
// Follows SRP - Single Responsibility Principle: only handles show command creation
func NewShowCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show various information and templates",
		Long: `Show various information and templates for the secrets CLI.

Available subcommands:
  template    Show the secrets.yml template`,
	}

	// Add subcommands
	cmd.AddCommand(NewShowTemplateCommand())

	return cmd
}

// NewShowTemplateCommand creates the show template subcommand
// Follows SRP - Single Responsibility Principle: only handles template display
func NewShowTemplateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Show the secrets.yml template",
		Long: `Show the secrets.yml template with examples and documentation.

This command displays the official secrets.yml template that demonstrates
all available features, field types, and configuration options.

Examples:
  secrets show template           # Show complete template with examples
  secrets show template --minimal # Show minimal template without comments`,
		RunE: func(cmd *cobra.Command, args []string) error {
			minimal, _ := cmd.Flags().GetBool("minimal")

			if minimal {
				// Generate minimal template without comments
				minimalTemplate := generateMinimalTemplate(showTemplateContent)
				_, err := cmd.OutOrStdout().Write([]byte(minimalTemplate))
				return err
			} else {
				// Show complete template
				_, err := cmd.OutOrStdout().Write([]byte(showTemplateContent))
				return err
			}
		},
	}

	// Add flags
	cmd.Flags().Bool("minimal", false, "show minimal template without comments and examples")

	return cmd
}

// generateMinimalTemplate removes comments and examples from the template
// Follows SRP - Single Responsibility Principle: only handles template processing
func generateMinimalTemplate(content string) string {
	lines := strings.Split(content, "\n")
	var minimalLines []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comment lines and empty lines, but keep YAML structure
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		minimalLines = append(minimalLines, line)
	}

	return strings.Join(minimalLines, "\n") + "\n"
}
