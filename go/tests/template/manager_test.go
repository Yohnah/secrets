package template_test

import (
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/template"
)

func TestNewManager_ReturnsManager(t *testing.T) {
	t.Parallel()
	mgr := template.NewManager()
	if mgr == nil {
		t.Fatal("Expected non-nil manager")
	}
}

func TestGetTemplate_SecretsYml_Success(t *testing.T) {
	t.Parallel()
	mgr := template.NewManager()

	content, err := mgr.GetTemplate(nil, config.SecretsYMLFilename)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if content == "" {
		t.Fatal("Expected non-empty template content")
	}

	// Verify template contains expected sections
	if !strings.Contains(content, "metadata:") {
		t.Error("Expected template to contain 'metadata:' section")
	}

	if !strings.Contains(content, "environments:") {
		t.Error("Expected template to contain 'environments:' section")
	}

	if !strings.Contains(content, "outputs:") {
		t.Error("Expected template to contain 'outputs:' section")
	}
}

func TestGetTemplate_NotFound(t *testing.T) {
	t.Parallel()
	mgr := template.NewManager()

	_, err := mgr.GetTemplate(nil, "nonexistent.yml")
	if err == nil {
		t.Fatal("Expected error for non-existent template")
	}

	expectedMsg := `template "nonexistent.yml" not found`
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got: '%s'", expectedMsg, err.Error())
	}
}

func TestGetTemplate_WithData_ReturnsRaw(t *testing.T) {
	t.Parallel()
	mgr := template.NewManager()

	// For now, data parameter is ignored and raw template is returned
	data := map[string]string{"key": "value"}
	content, err := mgr.GetTemplate(data, config.SecretsYMLFilename)

	// Data processing not yet implemented, but should not error
	// Just ignore data and return raw template
	if err != nil {
		t.Fatalf("Expected no error with data parameter, got: %v", err)
	}

	if content == "" {
		t.Fatal("Expected non-empty template content")
	}
}

func TestGetTemplate_EmptyName(t *testing.T) {
	t.Parallel()
	mgr := template.NewManager()

	_, err := mgr.GetTemplate(nil, "")
	if err == nil {
		t.Fatal("Expected error for empty template name")
	}
}

func TestGetTemplate_SecretsYml_ContainsDocumentation(t *testing.T) {
	t.Parallel()
	mgr := template.NewManager()

	content, err := mgr.GetTemplate(nil, config.SecretsYMLFilename)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify template contains helpful comments
	if !strings.Contains(content, "#") {
		t.Error("Expected template to contain comment lines for documentation")
	}
}

func TestRenderTemplate_Success(t *testing.T) {
	t.Parallel()
	mgr := template.NewManager()

	data := template.TemplateData{
		Section:     "production",
		Environment: "production",
		Profile:     "myapp",
		Items: map[string]string{
			"DB_PASSWORD": "secret123",
			"API_KEY":     "key456",
		},
	}

	// Test with dotenv template
	result, err := mgr.RenderTemplate("dotenv.env", data)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !strings.Contains(result, `DB_PASSWORD="secret123"`) {
		t.Error("Expected rendered template to contain DB_PASSWORD")
	}

	if !strings.Contains(result, `API_KEY="key456"`) {
		t.Error("Expected rendered template to contain API_KEY")
	}
}

func TestRenderTemplate_WithSection(t *testing.T) {
	t.Parallel()
	mgr := template.NewManager()

	data := template.TemplateData{
		Section:     "test-section",
		Environment: "test",
		Profile:     "app",
		Items: map[string]string{
			"VAR1": "value1",
		},
	}

	// Test with yaml template that uses Section
	result, err := mgr.RenderTemplate("yaml.yml", data)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !strings.Contains(result, "test-section:") {
		t.Error("Expected rendered template to contain section name")
	}

	if !strings.Contains(result, `VAR1: "value1"`) {
		t.Error("Expected rendered template to contain VAR1")
	}
}

func TestRenderTemplate_NotFound(t *testing.T) {
	t.Parallel()
	mgr := template.NewManager()

	data := template.TemplateData{
		Items: map[string]string{"key": "value"},
	}

	_, err := mgr.RenderTemplate("nonexistent.tpl", data)
	if err == nil {
		t.Fatal("Expected error for non-existent template")
	}

	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' error, got: %v", err)
	}
}

func TestRenderTemplate_Base64Encode(t *testing.T) {
	t.Parallel()
	mgr := template.NewManager()

	data := template.TemplateData{
		Section: "test",
		Items: map[string]string{
			"SECRET": "mysecret",
		},
	}

	// Test with k8s template that uses base64encode
	result, err := mgr.RenderTemplate("k8s.yml", data)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// "mysecret" in base64 is "bXlzZWNyZXQ="
	if !strings.Contains(result, "bXlzZWNyZXQ=") {
		t.Error("Expected rendered template to contain base64 encoded value")
	}
}

func TestRenderTemplate_EmptyItems(t *testing.T) {
	t.Parallel()
	mgr := template.NewManager()

	data := template.TemplateData{
		Section:     "empty",
		Environment: "test",
		Profile:     "app",
		Items:       map[string]string{},
	}

	result, err := mgr.RenderTemplate("dotenv.env", data)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// With empty items, result should contain the template header but no actual key=value pairs
	// Check that there are no assignments (no lines with =)
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && strings.Contains(trimmed, "=") {
			t.Errorf("Expected no variable assignments with empty items, found: %q", line)
		}
	}
}
