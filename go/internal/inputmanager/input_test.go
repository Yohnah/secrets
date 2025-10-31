package inputmanager

import (
	"testing"
)

// Mock implementations for testing
type mockCLIHandler struct{}

func (m *mockCLIHandler) GetCommand() string                               { return "test-command" }
func (m *mockCLIHandler) GetFlag(name string) (string, error)              { return "flag-value", nil }
func (m *mockCLIHandler) GetLocalFlag(name string) (string, error)         { return "local-value", nil }
func (m *mockCLIHandler) AskConfirmation(question string) (bool, error)    { return true, nil }
func (m *mockCLIHandler) AskPassword(prompt string) (string, error)        { return "password", nil }
func (m *mockCLIHandler) AskPasswordConfirm(prompt string) (string, error) { return "password", nil }

type mockEnvVarsHandler struct{}

func (m *mockEnvVarsHandler) Get(name string) (string, bool) {
	if name == "TEST_VAR" {
		return "test-value", true
	}
	return "", false
}
func (m *mockEnvVarsHandler) GetAll() map[string]string {
	return map[string]string{"TEST_VAR": "test-value"}
}

type mockFileReader struct{}

func (m *mockFileReader) ReadYAML(path string) (map[string]interface{}, error) {
	return map[string]interface{}{"key": "value"}, nil
}
func (m *mockFileReader) ReadRaw(path string) ([]byte, error) {
	return []byte("raw content"), nil
}

func TestNewInputManager(t *testing.T) {
	cli := &mockCLIHandler{}
	envVars := &mockEnvVarsHandler{}
	fileReader := &mockFileReader{}

	manager := NewInputManager(cli, envVars, fileReader)

	if manager == nil {
		t.Error("Expected non-nil input manager")
	}
}

func TestStandardInputManager_CLI(t *testing.T) {
	cli := &mockCLIHandler{}
	envVars := &mockEnvVarsHandler{}
	fileReader := &mockFileReader{}

	manager := NewInputManager(cli, envVars, fileReader)

	result := manager.CLI()
	if result == nil {
		t.Error("Expected non-nil CLI handler")
	}
	if result.GetCommand() != "test-command" {
		t.Errorf("Expected command 'test-command', got %q", result.GetCommand())
	}
}

func TestStandardInputManager_EnvVars(t *testing.T) {
	cli := &mockCLIHandler{}
	envVars := &mockEnvVarsHandler{}
	fileReader := &mockFileReader{}

	manager := NewInputManager(cli, envVars, fileReader)

	result := manager.EnvVars()
	if result == nil {
		t.Error("Expected non-nil EnvVars handler")
	}

	value, exists := result.Get("TEST_VAR")
	if !exists {
		t.Error("Expected TEST_VAR to exist")
	}
	if value != "test-value" {
		t.Errorf("Expected 'test-value', got %q", value)
	}
}

func TestStandardInputManager_ReadFile(t *testing.T) {
	cli := &mockCLIHandler{}
	envVars := &mockEnvVarsHandler{}
	fileReader := &mockFileReader{}

	manager := NewInputManager(cli, envVars, fileReader)

	result := manager.ReadFile()
	if result == nil {
		t.Error("Expected non-nil file reader")
	}

	data, err := result.ReadRaw("test.txt")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if string(data) != "raw content" {
		t.Errorf("Expected 'raw content', got %q", data)
	}
}
