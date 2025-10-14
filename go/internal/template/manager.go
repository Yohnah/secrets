package template

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

//go:embed templates/*.tpl.yml
var templatesFS embed.FS

// Template names handled by the manager.
const (
	SecretsTemplateName = "secrets.yml"
)

// Manager exposes template processing capabilities for the application.
type Manager interface {
	// GetTemplate returns the raw template content for the requested template name.
	// When data is nil, the template must be returned without processing.
	GetTemplate(data interface{}, name string) (string, error)
}

// GetAvailableTemplates returns a list of available template names
func GetAvailableTemplates() ([]string, error) {
	var templates []string

	err := fs.WalkDir(templatesFS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".tpl.yml") {
			name := strings.TrimSuffix(filepath.Base(path), ".tpl.yml") + ".yml"
			templates = append(templates, name)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to read embedded templates: %w", err)
	}

	return templates, nil
}

type manager struct {
	templates map[string]string
}

// NewManager creates a TemplateManager instance with embedded templates registered.
// Automatically loads all templates from the embedded templates/*.tpl.yml files.
func NewManager() Manager {
	templates := make(map[string]string)

	// Load all templates from embedded FS
	err := fs.WalkDir(templatesFS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".tpl.yml") {
			content, err := templatesFS.ReadFile(path)
			if err != nil {
				return err
			}
			// Map "k8s.tpl.yml" to "k8s.yml", "secrets.tpl.yml" to "secrets.yml"
			name := strings.TrimSuffix(filepath.Base(path), ".tpl.yml") + ".yml"
			templates[name] = string(content)
		}
		return nil
	})

	if err != nil {
		// This shouldn't happen with embedded files, but handle it gracefully
		panic(fmt.Sprintf("failed to load embedded templates: %v", err))
	}

	return &manager{
		templates: templates,
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
