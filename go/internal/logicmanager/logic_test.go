package logicmanager

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockConfig struct {
	dbName string
	dbPath string
}

func (m *mockConfig) LoadConfig() error                            { return nil }
func (m *mockConfig) HandleInteractiveConfirmationsForInit() error { return nil }
func (m *mockConfig) ObtainPassword() error                        { return nil }
func (m *mockConfig) GetDatabaseName() string                      { return m.dbName }
func (m *mockConfig) GetDatabasePath() string                      { return m.dbPath }
func (m *mockConfig) GetKeyfile() string                           { return "" }
func (m *mockConfig) GetPassword() string                          { return "test123" }
func (m *mockConfig) GetConfigPath() string                        { return "/tmp/config.yml" }
func (m *mockConfig) GetForceRecreate() bool                       { return false }
func (m *mockConfig) GetNoCreateDatabase() bool                    { return false }
func (m *mockConfig) GetNoKeyfile() bool                           { return true }
func (m *mockConfig) GetIgnoreConfigFile() bool                    { return true }
func (m *mockConfig) GetHomeDir() string                           { return "/tmp" }
func (m *mockConfig) IsNonInteractive() bool                       { return true }
func (m *mockConfig) ClearPassword()                               {}

type mockBD struct{}

func (m *mockBD) DatabaseExists(path string) bool                                   { return false }
func (m *mockBD) GenerateKeyfile(path string) error                                 { return nil }
func (m *mockBD) CreateDatabase(dbPath, password, keyfilePath, dbName string) error { return nil }
func (m *mockBD) DeleteDatabase(path string) error                                  { return nil }

type mockOutput struct{}

func (m *mockOutput) CreateDir(path string, mode os.FileMode) error                 { return nil }
func (m *mockOutput) WriteFile(path string, content []byte, mode os.FileMode) error { return nil }

type mockLogger struct{}

func (m *mockLogger) Debug(msg string)  {}
func (m *mockLogger) Info(msg string)   {}
func (m *mockLogger) Warn(msg string)   {}
func (m *mockLogger) Error(msg string)  {}
func (m *mockLogger) Fatal(msg string)  {}
func (m *mockLogger) SetVerbose(v bool) {}

func TestNewLogicManager(t *testing.T) {
	config := &mockConfig{dbName: "test", dbPath: "/tmp/test.kdbx"}
	bd := &mockBD{}
	output := &mockOutput{}
	logger := &mockLogger{}

	lm := NewLogicManager(config, bd, output, logger)

	assert.NotNil(t, lm)
}
