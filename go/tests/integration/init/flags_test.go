package init

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	integration "github.com/Yohnah/secrets/tests/integration"
	"github.com/stretchr/testify/suite"
)

// InitFlagsSuite tests flag combinations for init command
type InitFlagsSuite struct {
	integration.IntegrationSuite
}

// TestInitFlagsSuite runs the flags test suite
func TestInitFlagsSuite(t *testing.T) {
	suite.Run(t, new(InitFlagsSuite))
}

// TestFlags_CustomDatabaseName tests --database-name flag
func (s *InitFlagsSuite) TestFlags_CustomDatabaseName() {
	os.Setenv("SECRETS_PASSWORD", "123456")

	cmd := exec.Command(s.BinPath, "init",
		"--non-interactive",
		"--database-name", "staging",
	)
	output, err := cmd.CombinedOutput()

	s.NoError(err, "init with --database-name should succeed: %s", string(output))

	// Verify custom database directory
	configDir := s.TestPath(".secrets", "staging")
	integration.AssertDirExists(s.T(), configDir, "Custom database directory should exist")

	dbPath := filepath.Join(configDir, "secrets.kdbx")
	integration.AssertFileExists(s.T(), dbPath, "Database should exist in custom directory")

	// Verify config.yml references custom name
	configFile := s.TestPath(".secrets", "config.yml")
	configContent, err := os.ReadFile(configFile)
	s.NoError(err, "should read config file")
	// YAML serializer quotes string values
	s.True(
		strings.Contains(string(configContent), `name: "staging"`) || strings.Contains(string(configContent), "name: staging"),
		"Config should contain custom database name (with or without quotes)",
	)
}

// TestFlags_AbsoluteDatabasePath tests absolute path for database
func (s *InitFlagsSuite) TestFlags_AbsoluteDatabasePath() {
	os.Setenv("SECRETS_PASSWORD", "123456")

	absolutePath := s.TestPath("absolute", "secure.kdbx")

	cmd := exec.Command(s.BinPath, "init",
		"--non-interactive",
		"--database-path", absolutePath,
	)
	output, err := cmd.CombinedOutput()

	s.NoError(err, "init with absolute path should succeed: %s", string(output))

	// Verify database at absolute path
	integration.AssertFileExists(s.T(), absolutePath, "Database should exist at absolute path")

	// Verify config.yml references absolute path
	configFile := s.TestPath(".secrets", "config.yml")
	integration.AssertFileContains(s.T(), configFile, absolutePath, "Config should contain absolute path")
}

// TestFlags_CustomKeyfile tests --keyfile flag
func (s *InitFlagsSuite) TestFlags_CustomKeyfile() {
	os.Setenv("SECRETS_PASSWORD", "123456")

	keyfilePath := s.TestPath("custom.keyfile")

	cmd := exec.Command(s.BinPath, "init",
		"--non-interactive",
		"--keyfile", keyfilePath,
	)
	output, err := cmd.CombinedOutput()

	s.NoError(err, "init with --keyfile should succeed: %s", string(output))

	// Verify keyfile at custom path
	integration.AssertFileExists(s.T(), keyfilePath, "Keyfile should exist at custom path")

	// Verify config.yml references custom keyfile
	configFile := s.TestPath(".secrets", "config.yml")
	integration.AssertFileContains(s.T(), configFile, keyfilePath, "Config should reference custom keyfile")
}

// TestFlags_CustomConfig tests --config flag
func (s *InitFlagsSuite) TestFlags_CustomConfig() {
	os.Setenv("SECRETS_PASSWORD", "123456")

	customConfigPath := s.TestPath("custom-config.yml")

	cmd := exec.Command(s.BinPath, "init",
		"--non-interactive",
		"--config", customConfigPath,
	)
	output, err := cmd.CombinedOutput()

	s.NoError(err, "init with --config should succeed: %s", string(output))

	// Verify config created at custom path
	integration.AssertFileExists(s.T(), customConfigPath, "Config should exist at custom path")
}

// TestFlags_MultipleGlobal tests combination of multiple global flags
func (s *InitFlagsSuite) TestFlags_MultipleGlobal() {
	os.Setenv("SECRETS_PASSWORD", "123456")

	customConfig := s.TestPath("multi.yml")
	customDB := s.TestPath("multi.kdbx")
	customKeyfile := s.TestPath("multi.key")

	cmd := exec.Command(s.BinPath, "init",
		"--non-interactive",
		"--verbose",
		"--config", customConfig,
		"--database-name", "multi",
		"--database-path", customDB,
		"--keyfile", customKeyfile,
	)
	output, err := cmd.CombinedOutput()

	s.NoError(err, "init with multiple flags should succeed: %s", string(output))

	// Verify all custom paths
	integration.AssertFileExists(s.T(), customConfig, "Custom config should exist")
	integration.AssertFileExists(s.T(), customDB, "Custom database should exist")
	integration.AssertFileExists(s.T(), customKeyfile, "Custom keyfile should exist")

	// Verify verbose output
	outputStr := string(output)
	s.Contains(outputStr, "DEBUG", "Should show verbose output")
}

// TestFlags_GlobalAndLocal tests global + local flags combination
func (s *InitFlagsSuite) TestFlags_GlobalAndLocal() {
	os.Setenv("SECRETS_PASSWORD", "123456")

	cmd := exec.Command(s.BinPath, "init",
		"--non-interactive",
		"--verbose",
		"--database-name", "combined",
		"--no-keyfile",
		"--no-create-database",
	)
	output, err := cmd.CombinedOutput()

	s.NoError(err, "init with global+local flags should succeed: %s", string(output))

	// Verify config created
	configFile := s.TestPath(".secrets", "config.yml")
	integration.AssertFileExists(s.T(), configFile, "Config should exist")

	// Verify database NOT created (--no-create-database)
	configDir := s.TestPath(".secrets", "combined")
	dbPath := filepath.Join(configDir, "secrets.kdbx")
	integration.AssertFileNotExists(s.T(), dbPath, "Database should not exist")

	// Verify verbose output
	outputStr := string(output)
	s.Contains(outputStr, "DEBUG", "Should show verbose output")
}
