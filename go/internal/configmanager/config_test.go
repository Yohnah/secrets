package configmanager

import (
	"testing"

	"github.com/Yohnah/secrets/internal/inputmanager"
	"github.com/stretchr/testify/assert"
)

type mockInputManager struct{}

func (m *mockInputManager) CLI() inputmanager.CLIHandler         { return &mockCLI{} }
func (m *mockInputManager) EnvVars() inputmanager.EnvVarsHandler { return &mockEnv{} }
func (m *mockInputManager) ReadFile() inputmanager.FileReader    { return &mockFile{} }
func (m *mockInputManager) Prompts() inputmanager.PromptsHandler { return &mockPrompts{} }

type mockCLI struct{}

func (m *mockCLI) GetStringFlag(name string) (string, error) { return "", nil }
func (m *mockCLI) GetBoolFlag(name string) (bool, error)     { return false, nil }
func (m *mockCLI) GetCommand() string                        { return "" }

type mockEnv struct{}

func (m *mockEnv) Get(key string) (string, bool) { return "", false }
func (m *mockEnv) GetAll() map[string]string     { return map[string]string{} }

type mockFile struct{}

func (m *mockFile) ReadYAML(path string) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}
func (m *mockFile) ReadRaw(path string) ([]byte, error) { return []byte{}, nil }

type mockPrompts struct{}

func (m *mockPrompts) AskPasswordConfirm(prompt string) (string, error) { return "test123", nil }
func (m *mockPrompts) AskPassword(prompt string) (string, error)        { return "test123", nil }
func (m *mockPrompts) AskConfirmation(prompt string, defaultValue bool) (bool, error) {
	return true, nil
}
func (m *mockPrompts) AskText(prompt string) (string, error)                     { return "text", nil }
func (m *mockPrompts) AskChoice(prompt string, options []string) (string, error) { return "", nil }

type mockValidator struct{}

func (m *mockValidator) ValidateDatabaseName(name string) error { return nil }
func (m *mockValidator) ValidatePath(path string) error         { return nil }
func (m *mockValidator) ValidatePassword(password string) error { return nil }

type mockLogger struct{}

func (m *mockLogger) Debug(msg string)  {}
func (m *mockLogger) Info(msg string)   {}
func (m *mockLogger) Warn(msg string)   {}
func (m *mockLogger) Error(msg string)  {}
func (m *mockLogger) Fatal(msg string)  {}
func (m *mockLogger) SetVerbose(v bool) {}

func TestNewStandardConfig(t *testing.T) {
	inputMgr := &mockInputManager{}
	validator := &mockValidator{}
	logger := &mockLogger{}

	config := NewStandardConfig(inputMgr, validator, logger)

	assert.NotNil(t, config)
}

func TestConfigGetters(t *testing.T) {
	inputMgr := &mockInputManager{}
	validator := &mockValidator{}
	logger := &mockLogger{}
	config := NewStandardConfig(inputMgr, validator, logger)

	// LoadConfig initializes default values
	err := config.LoadConfig()
	assert.NoError(t, err)

	assert.NotEmpty(t, config.GetDatabaseName())
	assert.NotEmpty(t, config.GetDatabasePath())
	assert.NotEmpty(t, config.GetConfigPath())
}
