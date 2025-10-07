package show

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed templates/secrets.tpl.yml
var secretsTemplate string

// Template outputs the embedded secrets.yml template
func (s *service) Template() error {
	// Get configuration (ConfigMgr has already processed precedence)
	cfg, err := s.config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Get minimal flag from processed config
	minimal := cfg.Minimal

	var content string
	if minimal {
		content = s.processMinimalTemplate()
	} else {
		content = secretsTemplate
	}
	return s.output.OutputRaw(content)
}

// processMinimalTemplate generates a minimal version of the template
func (s *service) processMinimalTemplate() string {
	lines := strings.Split(secretsTemplate, "\n")
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
