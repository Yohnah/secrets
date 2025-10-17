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
	inComment := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check for start of Go template comment
		if strings.HasPrefix(trimmed, "{{- /*") {
			inComment = true
			continue
		}

		// Check for end of Go template comment
		if strings.HasPrefix(trimmed, "*/ -}}") {
			inComment = false
			continue
		}

		// Skip lines inside comments
		if inComment {
			continue
		}

		// Skip traditional comment lines (starting with #)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Skip empty lines
		if trimmed == "" {
			continue
		}

		// Include the line
		result.WriteString(line)
		result.WriteString("\n")
	}

	return result.String()
}
