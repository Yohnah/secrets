package show

import (
	"fmt"
	"strings"
)

// Template outputs the embedded template file
func (s *service) Template() error {
	// Get configuration (ConfigMgr has already processed precedence)
	cfg, err := s.config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Get template name from config (passed as argument from CLI)
	templateName := cfg.TemplateName
	if templateName == "" {
		return fmt.Errorf("template name is required")
	}

	// Pull template from TemplateManager (raw template, no processing)
	content, err := s.template.GetTemplate(nil, templateName)
	if err != nil {
		return fmt.Errorf("failed to get template %q: %w", templateName, err)
	}

	// Get minimal flag from processed config
	minimal := cfg.Minimal

	// If minimal flag is set, process the template
	if minimal {
		content = s.processMinimalTemplate(content)
	}

	return s.output.OutputRaw(content)
}

// processMinimalTemplate generates a minimal version of the template
func (s *service) processMinimalTemplate(templateContent string) string {
	lines := strings.Split(templateContent, "\n")
	var result strings.Builder
	inSkipSection := false

	for _, line := range lines {
		// Skip decorative lines
		if strings.HasPrefix(line, "# ═══════════════════") {
			continue
		}
		if strings.HasPrefix(line, "# SECRETS.YML TEMPLATE") {
			continue
		}
		if strings.Contains(line, "This file defines") {
			continue
		}

		// Detect start of COMPLETE EXAMPLE section
		if strings.Contains(line, "COMPLETE EXAMPLE") {
			inSkipSection = true
			continue
		}

		// Detect start of FIELD REFERENCE section
		if strings.Contains(line, "FIELD REFERENCE") {
			inSkipSection = true
			continue
		}

		// Detect end of skip section (when we find metadata or environments or outputs)
		if strings.HasPrefix(line, "metadata:") ||
			strings.HasPrefix(line, "environments:") ||
			strings.HasPrefix(line, "outputs:") {
			inSkipSection = false
		}

		// Skip lines in sections we're skipping
		if inSkipSection {
			continue
		}

		// Include the line
		result.WriteString(line)
		result.WriteString("\n")
	}

	return result.String()
}
