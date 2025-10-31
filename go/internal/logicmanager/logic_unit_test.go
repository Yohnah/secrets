package logicmanager

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Yohnah/secrets/internal/bdmanager"
	"github.com/Yohnah/secrets/internal/configmanager"
	"github.com/Yohnah/secrets/internal/inputmanager/cli"
	"github.com/Yohnah/secrets/internal/inputmanager/envvars"
	"github.com/Yohnah/secrets/internal/loggermanager"
	"github.com/Yohnah/secrets/internal/outputmanager"
	"github.com/Yohnah/secrets/internal/validatormanager"
	"github.com/spf13/cobra"
)

// ============================================================================
// Helper functions
// ============================================================================

func createTestLogicUnit(t *testing.T, configPath, dbName, dbPath, keyfile string, noKeyfile, ignoreConfig bool) *StandardLogic {
	t.Helper()

	logger := loggermanager.NewStderrLogger()
	validator := validatormanager.NewStandardValidator(logger)

	// Create cobra command for CLI
	cmd := &cobra.Command{}
	cmd.Flags().String("config", "", "")
	cmd.Flags().String("database-name", "", "")
	cmd.Flags().String("database-path", "", "")
	cmd.Flags().String("keyfile", "", "")
	cmd.Flags().Bool("non-interactive", false, "")
	cmd.Flags().Bool("ignore-config-file", false, "")
	cmd.Flags().Bool("no-keyfile", false, "")

	// Set flag values
	if configPath != "" {
		cmd.Flags().Set("config", configPath)
	}
	if dbName != "" {
		cmd.Flags().Set("database-name", dbName)
	}
	if dbPath != "" {
		cmd.Flags().Set("database-path", dbPath)
	}
	if keyfile != "" {
		cmd.Flags().Set("keyfile", keyfile)
	}
	if ignoreConfig {
		cmd.Flags().Set("ignore-config-file", "true")
	}
	if noKeyfile {
		cmd.Flags().Set("no-keyfile", "true")
	}

	cliReader := cli.NewCobraCliReader()
	cliReader.SetCommand(cmd)

	envReader := envvars.NewOsEnvVarsReader()
	output := outputmanager.NewStandardOutput(logger)
	bd := bdmanager.NewStandardBD(logger, validator)

	config := configmanager.NewStandardConfig(cliReader, envReader, validator, logger)
	config.LoadConfig()

	logic := NewStandardLogic(config, logger, validator, cliReader, envReader, output, bd)
	return logic.(*StandardLogic)
}

// ============================================================================
// Tests for configContainsDatabase()
// ============================================================================

func TestConfigContainsDatabase(t *testing.T) {
	logic := createTestLogicUnit(t, "", "default", "", "", false, false)

	tests := []struct {
		name     string
		content  string
		dbName   string
		expected bool
	}{
		{
			name: "Database with quotes exists",
			content: `database:
  name: "default"
  path: "secrets.kdbx"`,
			dbName:   "default",
			expected: true,
		},
		{
			name: "Database without quotes exists",
			content: `database:
  name: default
  path: secrets.kdbx`,
			dbName:   "default",
			expected: true,
		},
		{
			name: "Database not found",
			content: `database:
  name: "production"
  path: "secrets.kdbx"`,
			dbName:   "default",
			expected: false,
		},
		{
			name: "Multiple databases, target found with quotes",
			content: `database:
  name: "default"
---
database:
  name: "production"
---
database:
  name: "staging"`,
			dbName:   "production",
			expected: true,
		},
		{
			name: "Multiple databases, target found without quotes",
			content: `database:
  name: default
---
database:
  name: production
---
database:
  name: staging`,
			dbName:   "production",
			expected: true,
		},
		{
			name: "Multiple databases, target not found",
			content: `database:
  name: "default"
---
database:
  name: "production"`,
			dbName:   "development",
			expected: false,
		},
		{
			name:     "Empty content",
			content:  "",
			dbName:   "default",
			expected: false,
		},
		{
			name: "Partial match should not trigger false positive",
			content: `database:
  name: "default-prod"`,
			dbName:   "default",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := logic.configContainsDatabase(tt.content, tt.dbName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Tests for buildConfigYAML()
// ============================================================================

func TestBuildConfigYAML(t *testing.T) {
	tests := []struct {
		name          string
		databaseName  string
		databasePath  string
		keyfile       string
		noKeyfile     bool
		expectedLines []string
		notExpected   []string
	}{
		{
			name:         "Config with keyfile",
			databaseName: "default",
			databasePath: "secrets.kdbx",
			keyfile:      "secrets.key",
			noKeyfile:    false,
			expectedLines: []string{
				"database:",
				`  name: "default"`,
				`  path: "secrets.kdbx"`,
				`  keyfile: "secrets.key"`,
			},
		},
		{
			name:         "Config without keyfile",
			databaseName: "production",
			databasePath: "/secure/prod.kdbx",
			keyfile:      "",
			noKeyfile:    true,
			expectedLines: []string{
				"database:",
				`  name: "production"`,
				`  path: "/secure/prod.kdbx"`,
			},
			notExpected: []string{
				"keyfile:",
			},
		},
		{
			name:         "Config with custom name",
			databaseName: "my-custom-db",
			databasePath: "custom.kdbx",
			keyfile:      "custom.key",
			noKeyfile:    false,
			expectedLines: []string{
				`  name: "my-custom-db"`,
				`  path: "custom.kdbx"`,
				`  keyfile: "custom.key"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logic := createTestLogicUnit(t, "", tt.databaseName, tt.databasePath, tt.keyfile, tt.noKeyfile, false)

			// Execute
			result := logic.buildConfigYAML()

			// Verify expected lines
			for _, line := range tt.expectedLines {
				assert.Contains(t, result, line, "Expected line not found in config YAML")
			}

			// Verify lines that should NOT be present
			for _, line := range tt.notExpected {
				assert.NotContains(t, result, line, "Unexpected line found in config YAML")
			}
		})
	}
}

// ============================================================================
// Tests for createConfigFile()
// ============================================================================

func TestCreateConfigFile_NewConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yml")

	logic := createTestLogicUnit(t, configPath, "default", "secrets.kdbx", "secrets.key", false, false)

	err := logic.createConfigFile("", "")
	require.NoError(t, err)

	// Verify file created
	assert.FileExists(t, configPath)

	// Verify content
	content, err := os.ReadFile(configPath)
	require.NoError(t, err)

	contentStr := string(content)
	assert.Contains(t, contentStr, `name: "default"`)
	assert.Contains(t, contentStr, `path: "secrets.kdbx"`)
	assert.Contains(t, contentStr, `keyfile: "secrets.key"`)
	assert.NotContains(t, contentStr, "---", "New config should not have separator")
}

func TestCreateConfigFile_AppendNewDatabase(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yml")

	// Create initial config
	initialContent := `database:
  name: "default"
  path: "secrets.kdbx"
  keyfile: "secrets.key"
`
	err := os.WriteFile(configPath, []byte(initialContent), 0600)
	require.NoError(t, err)

	// Append second database
	logic := createTestLogicUnit(t, configPath, "production", "prod.kdbx", "prod.key", false, false)

	err = logic.createConfigFile("", "")
	require.NoError(t, err)

	// Verify content
	content, err := os.ReadFile(configPath)
	require.NoError(t, err)

	contentStr := string(content)

	// Verify both databases present
	assert.Contains(t, contentStr, `name: "default"`)
	assert.Contains(t, contentStr, `name: "production"`)

	// Verify separator present
	assert.Contains(t, contentStr, "---")

	// Verify order (original first, new second)
	defaultIdx := strings.Index(contentStr, `name: "default"`)
	prodIdx := strings.Index(contentStr, `name: "production"`)
	assert.Less(t, defaultIdx, prodIdx, "Original database should come before new one")
}

func TestCreateConfigFile_DuplicateDatabase(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yml")

	// Create initial config with database
	initialContent := `database:
  name: "default"
  path: "secrets.kdbx"
  keyfile: "secrets.key"
`
	err := os.WriteFile(configPath, []byte(initialContent), 0600)
	require.NoError(t, err)

	// Try to create same database again
	logic := createTestLogicUnit(t, configPath, "default", "secrets.kdbx", "secrets.key", false, false)

	err = logic.createConfigFile("", "")
	require.NoError(t, err)

	// Verify content unchanged (no duplication)
	content, err := os.ReadFile(configPath)
	require.NoError(t, err)

	contentStr := string(content)

	// Should NOT have separator (only one database)
	assert.NotContains(t, contentStr, "---")

	// Count occurrences of database name (should be exactly 1)
	count := strings.Count(contentStr, `name: "default"`)
	assert.Equal(t, 1, count, "Database should appear exactly once")
}

func TestCreateConfigFile_IgnoreConfigFileFlag(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yml")
	dbPath := filepath.Join(tempDir, "test.kdbx")

	logic := createTestLogicUnit(t, configPath, "default", dbPath, "", true, true)

	err := logic.createConfigFile("", "")
	require.NoError(t, err)

	// Verify file NOT created
	assert.NoFileExists(t, configPath)
}

func TestCreateConfigFile_MultipleAppends(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yml")

	databases := []struct {
		name    string
		path    string
		keyfile string
	}{
		{"default", "default.kdbx", "default.key"},
		{"staging", "staging.kdbx", "staging.key"},
		{"production", "production.kdbx", "production.key"},
	}

	for _, db := range databases {
		logic := createTestLogicUnit(t, configPath, db.name, db.path, db.keyfile, false, false)

		err := logic.createConfigFile("", "")
		require.NoError(t, err)
	}

	// Verify all databases present
	content, err := os.ReadFile(configPath)
	require.NoError(t, err)

	contentStr := string(content)

	for _, db := range databases {
		assert.Contains(t, contentStr, fmt.Sprintf(`name: "%s"`, db.name))
	}

	// Verify correct number of separators (n-1 for n databases)
	separatorCount := strings.Count(contentStr, "---")
	assert.Equal(t, len(databases)-1, separatorCount)
}
