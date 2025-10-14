package template_test

import (
	"strings"
	"testing"

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

	content, err := mgr.GetTemplate(nil, "secrets.yml")
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
	content, err := mgr.GetTemplate(data, "secrets.yml")

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

	content, err := mgr.GetTemplate(nil, "secrets.yml")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify template contains helpful comments
	if !strings.Contains(content, "#") {
		t.Error("Expected template to contain comment lines for documentation")
	}
}
