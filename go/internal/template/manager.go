package template

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/big"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

//go:embed templates/*.tpl.*
var templatesFS embed.FS

// TemplateData defines the structure passed to templates for rendering
type TemplateData struct {
	Section     string            `json:"section"`
	Environment string            `json:"environment"`
	Profile     string            `json:"profile"`
	Items       map[string]string `json:"items"`
}

// Template names handled by the manager.
const (
	SecretsTemplateName = "secrets.yml"
)

// Manager exposes template processing capabilities for the application.
type Manager interface {
	// GetTemplate returns the raw template content for the requested template name.
	// When data is nil, the template must be returned without processing.
	GetTemplate(data interface{}, name string) (string, error)

	// RenderTemplate renders a template with the provided data.
	// Returns the rendered output or an error if rendering fails.
	RenderTemplate(name string, data TemplateData) (string, error)
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

	// The current implementation returns raw template content when data is nil
	_ = data

	return templateContent, nil
}

// RenderTemplate renders a template with the provided data using Go templates.
func (m *manager) RenderTemplate(name string, data TemplateData) (string, error) {
	templateContent, ok := m.templates[name]
	if !ok {
		return "", fmt.Errorf("template %q not found", name)
	}

	// Create a new template with custom functions
	tmpl, err := template.New(name).Funcs(getFuncMap()).Parse(templateContent)
	if err != nil {
		return "", fmt.Errorf("failed to parse template %q: %w", name, err)
	}

	// Execute the template with the provided data
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template %q: %w", name, err)
	}

	return buf.String(), nil
}

// getFuncMap returns a template.FuncMap with custom functions for templates
func getFuncMap() template.FuncMap {
	return template.FuncMap{
		// Encoding/Decoding functions
		"base64encode": func(s string) string {
			return base64.StdEncoding.EncodeToString([]byte(s))
		},
		"base64decode": func(s string) (string, error) {
			data, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				return "", err
			}
			return string(data), nil
		},
		"urlencode": func(s string) string {
			return strings.ReplaceAll(s, " ", "%20")
		},
		"urldecode": func(s string) string {
			return strings.ReplaceAll(s, "%20", " ")
		},

		// Data format functions
		"toJSON": func(v interface{}) (string, error) {
			data, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			return string(data), nil
		},
		"toYAML": func(v interface{}) (string, error) {
			data, err := yaml.Marshal(v)
			if err != nil {
				return "", err
			}
			return string(data), nil
		},
		"fromJSON": func(s string) (interface{}, error) {
			var result interface{}
			err := json.Unmarshal([]byte(s), &result)
			return result, err
		},

		// String manipulation functions
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"title": strings.Title,
		"trim":  strings.TrimSpace,
		"quote": func(s string) string {
			return fmt.Sprintf("%q", s)
		},
		"unquote": func(s string) string {
			return strings.Trim(s, `"'`)
		},
		"replace": func(old, new, s string) string {
			return strings.ReplaceAll(s, old, new)
		},
		"substr": func(start, length int, s string) string {
			if start < 0 || start >= len(s) {
				return ""
			}
			end := start + length
			if end > len(s) {
				end = len(s)
			}
			return s[start:end]
		},

		// Collection functions
		"join": func(sep string, items []string) string {
			return strings.Join(items, sep)
		},
		"split": strings.Split,
		"first": func(items []interface{}) interface{} {
			if len(items) == 0 {
				return nil
			}
			return items[0]
		},
		"last": func(items []interface{}) interface{} {
			if len(items) == 0 {
				return nil
			}
			return items[len(items)-1]
		},
		"len": func(v interface{}) int {
			switch val := v.(type) {
			case string:
				return len(val)
			case []interface{}:
				return len(val)
			case map[string]interface{}:
				return len(val)
			default:
				return 0
			}
		},

		// Control functions
		"default": func(defaultVal, val interface{}) interface{} {
			if val == nil || val == "" {
				return defaultVal
			}
			return val
		},
		"empty": func(val interface{}) bool {
			return val == nil || val == ""
		},
		"not": func(val bool) bool {
			return !val
		},

		// Math functions
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"mul": func(a, b int) int { return a * b },
		"div": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a / b
		},

		// Date/Time functions
		"now": time.Now,
		"date": func(format string, t time.Time) string {
			return t.Format(format)
		},

		// Hashing functions
		"sha256": func(s string) string {
			hash := sha256.Sum256([]byte(s))
			return fmt.Sprintf("%x", hash)
		},
		"md5": func(s string) string {
			hash := md5.Sum([]byte(s))
			return fmt.Sprintf("%x", hash)
		},

		// Identification functions
		"uuid": func() string {
			return uuid.New().String()
		},
		"random": func(max int) int {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
			if err != nil {
				return 0
			}
			return int(n.Int64())
		},
	}
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
