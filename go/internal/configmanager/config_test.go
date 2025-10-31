package configmanager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/inputmanager/cli"
	"github.com/Yohnah/secrets/internal/inputmanager/envvars"
	"github.com/Yohnah/secrets/internal/loggermanager"
	"github.com/Yohnah/secrets/internal/validatormanager"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestPath_String(t *testing.T) {
	tests := []struct {
		name     string
		path     Path
		expected string
	}{
		{
			name:     "empty path",
			path:     Path(""),
			expected: "",
		},
		{
			name:     "unix absolute path",
			path:     Path("/home/user/.secrets/db.kdbx"),
			expected: filepath.FromSlash("/home/user/.secrets/db.kdbx"),
		},
		{
			name:     "unix relative path",
			path:     Path("./secrets/db.kdbx"),
			expected: filepath.FromSlash("./secrets/db.kdbx"),
		},
		{
			name:     "windows-style with forward slashes",
			path:     Path("C:/SecureData/mydb.kdbx"),
			expected: filepath.FromSlash("C:/SecureData/mydb.kdbx"),
		},
		{
			name:     "path with multiple segments",
			path:     Path("data/secrets/production/db.kdbx"),
			expected: filepath.FromSlash("data/secrets/production/db.kdbx"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.path.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestStandardConfig_PathFields(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	validator := validatormanager.NewStandardValidator(logger)
	cliReader := cli.NewCobraCliReader()
	envReader := envvars.NewOsEnvVarsReader()

	config := NewStandardConfig(cliReader, envReader, validator, logger).(*StandardConfig)

	// Test SetDatabasePath + GetDatabasePath
	testPath := "C:/Data/test.kdbx"
	config.databasePath = Path(testPath)

	result := config.GetDatabasePath()
	expected := filepath.FromSlash(testPath)

	assert.Equal(t, expected, result, "GetDatabasePath should normalize path")

	// Test SetKeyfile + GetKeyfile
	keyfilePath := "/secure/keys/test.key"
	config.keyfile = Path(keyfilePath)

	keyfileResult := config.GetKeyfile()
	expectedKeyfile := filepath.FromSlash(keyfilePath)

	assert.Equal(t, expectedKeyfile, keyfileResult, "GetKeyfile should normalize path")

	// Test SetConfigPath + GetConfigPath
	configPath := "./config/secrets.yml"
	config.configPath = Path(configPath)

	configResult := config.GetConfigPath()
	expectedConfig := filepath.FromSlash(configPath)

	assert.Equal(t, expectedConfig, configResult, "GetConfigPath should normalize path")
}

func TestStandardConfig_Defaults(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	validator := validatormanager.NewStandardValidator(logger)
	cliReader := cli.NewCobraCliReader()
	envReader := envvars.NewOsEnvVarsReader()

	config := NewStandardConfig(cliReader, envReader, validator, logger)

	cmd := &cobra.Command{}
	cmd.Flags().String("config", "", "")
	cmd.Flags().String("database-name", "", "")
	cmd.Flags().String("database-path", "", "")
	cmd.Flags().String("keyfile", "", "")
	cmd.Flags().String("secrets-file", "", "")
	cmd.Flags().Bool("verbose", false, "")
	cmd.Flags().Bool("non-interactive", false, "")
	cmd.Flags().Bool("ignore-config-file", false, "")

	cliReader.SetCommand(cmd)

	err := config.LoadConfig()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if config.GetDatabaseName() != "default" {
		t.Errorf("Expected default database name, got %q", config.GetDatabaseName())
	}
	if config.GetDatabasePath() != "secrets.kdbx" {
		t.Errorf("Expected default database path, got %q", config.GetDatabasePath())
	}
}

func TestStandardConfig_EnvVarPrecedence(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	validator := validatormanager.NewStandardValidator(logger)
	cliReader := cli.NewCobraCliReader()
	envReader := envvars.NewOsEnvVarsReader()

	// Set env var
	os.Setenv("SECRETS_DATABASE", "/tmp/test.kdbx")
	defer os.Unsetenv("SECRETS_DATABASE")

	config := NewStandardConfig(cliReader, envReader, validator, logger)

	cmd := &cobra.Command{}
	cmd.Flags().String("config", "", "")
	cmd.Flags().String("database-name", "", "")
	cmd.Flags().String("database-path", "", "")
	cmd.Flags().String("keyfile", "", "")
	cmd.Flags().String("secrets-file", "", "")
	cmd.Flags().Bool("verbose", false, "")
	cmd.Flags().Bool("non-interactive", false, "")
	cmd.Flags().Bool("ignore-config-file", false, "")

	cliReader.SetCommand(cmd)

	err := config.LoadConfig()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if config.GetDatabasePath() != "/tmp/test.kdbx" {
		t.Errorf("Expected env var value, got %q", config.GetDatabasePath())
	}
}

func TestStandardConfig_FlagPrecedence(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	validator := validatormanager.NewStandardValidator(logger)
	cliReader := cli.NewCobraCliReader()
	envReader := envvars.NewOsEnvVarsReader()

	// Set env var
	os.Setenv("SECRETS_DATABASE", "/tmp/test.kdbx")
	defer os.Unsetenv("SECRETS_DATABASE")

	config := NewStandardConfig(cliReader, envReader, validator, logger)

	cmd := &cobra.Command{}
	cmd.Flags().String("config", "", "")
	cmd.Flags().String("database-name", "", "")
	cmd.Flags().String("database-path", "", "")
	cmd.Flags().String("keyfile", "", "")
	cmd.Flags().String("secrets-file", "", "")
	cmd.Flags().Bool("verbose", false, "")
	cmd.Flags().Bool("non-interactive", false, "")
	cmd.Flags().Bool("ignore-config-file", false, "")

	// Set flag (should override env var)
	cmd.Flags().Set("database-path", "/secure/prod.kdbx")

	cliReader.SetCommand(cmd)

	err := config.LoadConfig()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if config.GetDatabasePath() != "/secure/prod.kdbx" {
		t.Errorf("Expected flag value, got %q", config.GetDatabasePath())
	}
}
