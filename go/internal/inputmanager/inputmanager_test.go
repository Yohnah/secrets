package inputmanager

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStandardInputManager(t *testing.T) {
	t.Run("NewInputManager creates instance", func(t *testing.T) {
		cli := &mockCLIHandler{}
		prompts := &mockPromptsHandler{}
		env := &mockEnvVarsHandler{}
		file := &mockFileReader{}

		mgr := NewInputManager(cli, env, file, prompts)

		assert.NotNil(t, mgr)
		assert.Equal(t, cli, mgr.CLI())
		assert.Equal(t, prompts, mgr.Prompts())
		assert.Equal(t, env, mgr.EnvVars())
		assert.Equal(t, file, mgr.ReadFile())
	})
}

type mockCLIHandler struct{}

func (m *mockCLIHandler) GetStringFlag(name string) (string, error) { return "", nil }
func (m *mockCLIHandler) GetBoolFlag(name string) (bool, error)     { return false, nil }
func (m *mockCLIHandler) GetCommand() string                        { return "" }

type mockPromptsHandler struct{}

func (m *mockPromptsHandler) AskPasswordConfirm(prompt string) (string, error) { return "", nil }
func (m *mockPromptsHandler) AskPassword(prompt string) (string, error)        { return "", nil }
func (m *mockPromptsHandler) AskConfirmation(prompt string, defaultYes bool) (bool, error) {
	return false, nil
}
func (m *mockPromptsHandler) AskText(prompt string) (string, error) { return "", nil }
func (m *mockPromptsHandler) AskChoice(prompt string, options []string) (string, error) {
	return "", nil
}

type mockEnvVarsHandler struct{}

func (m *mockEnvVarsHandler) Get(key string) (string, bool) { return "", false }
func (m *mockEnvVarsHandler) GetAll() map[string]string     { return map[string]string{} }

type mockFileReader struct{}

func (m *mockFileReader) ReadYAML(path string) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}
func (m *mockFileReader) ReadRaw(path string) ([]byte, error) { return []byte{}, nil }
