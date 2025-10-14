package template

import (
	_ "embed"
	"fmt"
)

// Template names handled by the manager.
const (
	SecretsTemplateName = "secrets.yml"
)

//go:embed templates/secrets.tpl.yml
var secretsTemplate string

// Manager exposes template processing capabilities for the application.
type Manager interface {
	// GetTemplate returns the raw template content for the requested template name.
	// When data is nil, the template must be returned without processing.
	GetTemplate(data interface{}, name string) (string, error)
}

type manager struct {
	templates map[string]string
}

// NewManager creates a TemplateManager instance with embedded templates registered.
func NewManager() Manager {
	return &manager{
		templates: map[string]string{
			SecretsTemplateName: secretsTemplate,
		},
	}
}

// GetTemplate returns the requested template stored in the manager.
func (m *manager) GetTemplate(data interface{}, name string) (string, error) {
	templateContent, ok := m.templates[name]
	if !ok {
		return "", fmt.Errorf("template %q not found", name)
	}

	// The current implementation returns raw template content when data is nil,
	// keeping a placeholder for future processing logic.
	_ = data

	return templateContent, nil
}
