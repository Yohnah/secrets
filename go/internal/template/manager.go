package template

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

//go:embed templates/*.tpl.*
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
		if !d.IsDir() && strings.HasPrefix(path, "templates/") {
			baseName := filepath.Base(path)
			var name string

			// Handle different template types
			if strings.HasSuffix(baseName, ".tpl.yml") {
				name = strings.TrimSuffix(baseName, ".tpl.yml") + ".yml"
			} else if strings.HasPrefix(baseName, "shell.tpl.") {
				// Handle shell templates: shell.tpl.sh -> shell.sh, etc.
				ext := strings.TrimPrefix(baseName, "shell.tpl.")
				name = "shell." + ext
			} else if strings.HasSuffix(baseName, ".tpl.env") {
				name = strings.TrimSuffix(baseName, ".tpl.env") + ".env"
			} else if strings.HasSuffix(baseName, ".tpl.json") {
				name = strings.TrimSuffix(baseName, ".tpl.json") + ".json"
			} else if strings.HasSuffix(baseName, ".tpl.properties") {
				name = strings.TrimSuffix(baseName, ".tpl.properties") + ".properties"
			} else if strings.HasSuffix(baseName, ".tpl.tfvars") {
				name = strings.TrimSuffix(baseName, ".tpl.tfvars") + ".tfvars"
			} else if strings.HasSuffix(baseName, ".tpl.toml") {
				name = strings.TrimSuffix(baseName, ".tpl.toml") + ".toml"
			} else if strings.HasSuffix(baseName, ".tpl.cmd") {
				name = strings.TrimSuffix(baseName, ".tpl.cmd") + ".cmd"
			} else {
				return nil // Skip unknown template types
			}

			templates = append(templates, name)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to read embedded templates: %w", err)
	}

	return templates, nil
}

// GetAvailableTemplatesWithDescriptions returns a map of template names to their descriptions
func GetAvailableTemplatesWithDescriptions() (map[string]string, error) {
	templates := make(map[string]string)

	err := fs.WalkDir(templatesFS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasPrefix(path, "templates/") {
			baseName := filepath.Base(path)
			var name string

			// Handle different template types
			if strings.HasSuffix(baseName, ".tpl.yml") {
				name = strings.TrimSuffix(baseName, ".tpl.yml") + ".yml"
			} else if strings.HasPrefix(baseName, "shell.tpl.") {
				// Handle shell templates: shell.tpl.sh -> shell.sh, etc.
				ext := strings.TrimPrefix(baseName, "shell.tpl.")
				name = "shell." + ext
			} else if strings.HasSuffix(baseName, ".tpl.env") {
				name = strings.TrimSuffix(baseName, ".tpl.env") + ".env"
			} else if strings.HasSuffix(baseName, ".tpl.json") {
				name = strings.TrimSuffix(baseName, ".tpl.json") + ".json"
			} else if strings.HasSuffix(baseName, ".tpl.properties") {
				name = strings.TrimSuffix(baseName, ".tpl.properties") + ".properties"
			} else if strings.HasSuffix(baseName, ".tpl.tfvars") {
				name = strings.TrimSuffix(baseName, ".tpl.tfvars") + ".tfvars"
			} else if strings.HasSuffix(baseName, ".tpl.toml") {
				name = strings.TrimSuffix(baseName, ".tpl.toml") + ".toml"
			} else if strings.HasSuffix(baseName, ".tpl.cmd") {
				name = strings.TrimSuffix(baseName, ".tpl.cmd") + ".cmd"
			} else {
				return nil // Skip unknown template types
			}

			// Read the first few lines to find description
			content, err := templatesFS.ReadFile(path)
			if err != nil {
				return err
			}

			description := "Template file"
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "#") && len(strings.TrimSpace(strings.TrimPrefix(line, "#"))) > 0 {
					// Skip the header separator line
					if strings.Contains(line, "=====") {
						continue
					}
					// Found a comment line with content (should be the title)
					description = strings.TrimSpace(strings.TrimPrefix(line, "#"))
					// Convert from CAPITALIZED_SNAKE_CASE to normal case if needed
					description = normalizeDescription(description)
					break
				}
			}

			templates[name] = description
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
// Automatically loads all templates from the embedded templates/*.tpl.* files.
func NewManager() Manager {
	templates := make(map[string]string)

	// Load all templates from embedded FS
	err := fs.WalkDir(templatesFS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasPrefix(path, "templates/") {
			baseName := filepath.Base(path)
			var name string

			content, err := templatesFS.ReadFile(path)
			if err != nil {
				return err
			}

			// Handle different template types
			if strings.HasSuffix(baseName, ".tpl.yml") {
				name = strings.TrimSuffix(baseName, ".tpl.yml") + ".yml"
			} else if strings.HasPrefix(baseName, "shell.tpl.") {
				// Handle shell templates: shell.tpl.sh -> shell.sh, etc.
				ext := strings.TrimPrefix(baseName, "shell.tpl.")
				name = "shell." + ext
			} else if strings.HasSuffix(baseName, ".tpl.env") {
				name = strings.TrimSuffix(baseName, ".tpl.env") + ".env"
			} else if strings.HasSuffix(baseName, ".tpl.json") {
				name = strings.TrimSuffix(baseName, ".tpl.json") + ".json"
			} else if strings.HasSuffix(baseName, ".tpl.properties") {
				name = strings.TrimSuffix(baseName, ".tpl.properties") + ".properties"
			} else if strings.HasSuffix(baseName, ".tpl.tfvars") {
				name = strings.TrimSuffix(baseName, ".tpl.tfvars") + ".tfvars"
			} else if strings.HasSuffix(baseName, ".tpl.toml") {
				name = strings.TrimSuffix(baseName, ".tpl.toml") + ".toml"
			} else if strings.HasSuffix(baseName, ".tpl.cmd") {
				name = strings.TrimSuffix(baseName, ".tpl.cmd") + ".cmd"
			} else {
				return nil // Skip unknown template types
			}

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

// normalizeDescription converts template titles from various formats to readable descriptions
func normalizeDescription(description string) string {
	// Handle specific cases
	switch description {
	case "secret.yml definition template":
		return "Secrets configuration template"
	case "Shell Environment Export Template":
		return "Shell script for environment variables"
	case "Kubernetes Secret Template":
		return "Kubernetes Secret YAML resource"
	case "Secrets Configuration Template":
		return "Secrets configuration template"
	case "C Shell Environment Variables Template":
		return "C shell script for environment variables"
	case "Fish Shell Environment Variables Template":
		return "Fish shell script for environment variables"
	case "Nushell Environment Variables Template":
		return "Nushell script for environment variables"
	case "PowerShell Environment Variables Template":
		return "PowerShell script for environment variables"
	case "Ansible Variables Template":
		return "Ansible variables YAML file"
	case "Docker Compose Environment Template":
		return "Docker Compose environment variables"
	case "Dotenv Environment Variables Template":
		return "Environment variables .env file"
	case ".NET AppSettings JSON Template":
		return ".NET application settings JSON"
	case "JSON Configuration Template":
		return "JSON configuration file"
	case "Windows CMD Environment Variables Template":
		return "Windows CMD batch script"
	case "Spring Boot Properties Template":
		return "Spring Boot properties file"
	case "Terraform Variables Template":
		return "Terraform variables file"
	case "TOML Configuration Template":
		return "TOML configuration file"
	case "YAML Configuration Template":
		return "YAML configuration file"
	default:
		// Convert from Title Case to readable format
		// Replace spaces with spaces, handle acronyms, etc.
		return strings.Title(strings.ToLower(description))
	}
}
