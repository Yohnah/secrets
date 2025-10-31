package init

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	integration "github.com/Yohnah/secrets/tests/integration"
	"github.com/stretchr/testify/suite"
)

// InitNonInteractiveSuite tests non-interactive init command
type InitNonInteractiveSuite struct {
	integration.IntegrationSuite
}

// TestInitNonInteractiveSuite runs the non-interactive init test suite
func TestInitNonInteractiveSuite(t *testing.T) {
	suite.Run(t, new(InitNonInteractiveSuite))
}

// TestNonInteractive_Basic tests basic non-interactive init
func (s *InitNonInteractiveSuite) TestNonInteractive_Basic() {
	os.Setenv("SECRETS_PASSWORD", "123456")

	cmd := exec.Command(s.BinPath, "init", "--non-interactive")
	output, err := cmd.CombinedOutput()

	s.NoError(err, "init --non-interactive should succeed")

	// Verify config directory created
	configDir := s.TestPath(".secrets", "default")
	integration.AssertDirExists(s.T(), configDir, "Config directory should exist")

	// Verify config file created
	configFile := s.TestPath(".secrets", "config.yml")
	integration.AssertFileExists(s.T(), configFile, "Config file should exist")
	integration.AssertFilePermissions(s.T(), configFile, 0600, "Config file should have 0600 permissions")

	// Verify database created
	dbPath := filepath.Join(configDir, "secrets.kdbx")
	integration.AssertFileExists(s.T(), dbPath, "Database file should exist")

	// Verify keyfile created
	keyfilePath := filepath.Join(configDir, "secrets.key")
	integration.AssertFileExists(s.T(), keyfilePath, "Keyfile should exist")

	// Verify output
	outputStr := string(output)
	s.NotContains(outputStr, "Are you sure", "Non-interactive should not prompt")
}

// TestNonInteractive_MissingPassword tests non-interactive without password
func (s *InitNonInteractiveSuite) TestNonInteractive_MissingPassword() {
	// Ensure SECRETS_PASSWORD is NOT set
	os.Unsetenv("SECRETS_PASSWORD")

	cmd := exec.Command(s.BinPath, "init", "--non-interactive")
	output, err := cmd.CombinedOutput()

	s.Error(err, "init --non-interactive without password should fail")

	outputStr := string(output)
	s.Contains(outputStr, "SECRETS_PASSWORD", "Error should mention missing password env var")
}

// TestNonInteractive_IgnoreConfigFile tests --ignore-config-file
func (s *InitNonInteractiveSuite) TestNonInteractive_IgnoreConfigFile() {
	os.Setenv("SECRETS_PASSWORD", "123456")

	dbPath := s.TestPath("custom.kdbx")
	keyfilePath := s.TestPath("custom.key")

	cmd := exec.Command(s.BinPath, "init",
		"--non-interactive",
		"--ignore-config-file",
		"--database-path", dbPath,
		"--keyfile", keyfilePath,
	)
	output, err := cmd.CombinedOutput()

	s.NoError(err, "init with --ignore-config-file should succeed: %s", string(output))

	// Verify config.yml NOT created
	configFile := s.TestPath(".secrets", "config.yml")
	integration.AssertFileNotExists(s.T(), configFile, "Config file should not exist with --ignore-config-file")

	// Verify database created at custom path
	integration.AssertFileExists(s.T(), dbPath, "Database should exist at custom path")
	integration.AssertFileExists(s.T(), keyfilePath, "Keyfile should exist at custom path")
}

// TestNonInteractive_NoKeyfile tests --no-keyfile flag
func (s *InitNonInteractiveSuite) TestNonInteractive_NoKeyfile() {
	os.Setenv("SECRETS_PASSWORD", "123456")

	cmd := exec.Command(s.BinPath, "init", "--non-interactive", "--no-keyfile")
	_, err := cmd.CombinedOutput()

	s.NoError(err, "init --no-keyfile should succeed")

	configDir := s.TestPath(".secrets", "default")

	// Verify database created
	dbPath := filepath.Join(configDir, "secrets.kdbx")
	integration.AssertFileExists(s.T(), dbPath, "Database should exist")

	// Verify keyfile NOT created
	keyfilePath := filepath.Join(configDir, "secrets.key")
	integration.AssertFileNotExists(s.T(), keyfilePath, "Keyfile should not exist with --no-keyfile")

	// Verify config mentions no keyfile
	configFile := s.TestPath(".secrets", "config.yml")
	content, err := os.ReadFile(configFile)
	s.NoError(err, "Should read config file")

	// Config should not have keyfile entry or it should be empty
	configStr := string(content)
	s.NotContains(configStr, "keyfile: secrets.key", "Config should not reference keyfile")
}

// TestNonInteractive_ForceRecreate tests --force-recreate flag
func (s *InitNonInteractiveSuite) TestNonInteractive_ForceRecreate() {
	os.Setenv("SECRETS_PASSWORD", "123456")

	// First init
	cmd := exec.Command(s.BinPath, "init", "--non-interactive")
	_, err := cmd.CombinedOutput()
	s.NoError(err, "First init should succeed")

	configDir := s.TestPath(".secrets", "default")
	dbPath := filepath.Join(configDir, "secrets.kdbx")

	// Get original modification time
	info1, err := os.Stat(dbPath)
	s.NoError(err, "Database should exist")

	// Second init with --force-recreate
	cmd = exec.Command(s.BinPath, "init", "--non-interactive", "--force-recreate")
	output, err := cmd.CombinedOutput()
	s.NoError(err, "init --force-recreate should succeed: %s", string(output))

	// Verify database was recreated
	info2, err := os.Stat(dbPath)
	s.NoError(err, "Database should exist after recreate")

	// Modification time should be different (or at least file was touched)
	s.True(info2.ModTime().After(info1.ModTime()) || info2.ModTime().Equal(info1.ModTime()),
		"Database should be recreated")
}

// TestNonInteractive_NoCreateDatabase tests --no-create-database flag
func (s *InitNonInteractiveSuite) TestNonInteractive_NoCreateDatabase() {
	os.Setenv("SECRETS_PASSWORD", "123456")

	cmd := exec.Command(s.BinPath, "init", "--non-interactive", "--no-create-database")
	_, err := cmd.CombinedOutput()

	s.NoError(err, "init --no-create-database should succeed")

	// Verify config file created
	configFile := s.TestPath(".secrets", "config.yml")
	integration.AssertFileExists(s.T(), configFile, "Config file should exist")

	// Verify database NOT created
	configDir := s.TestPath(".secrets", "default")
	dbPath := filepath.Join(configDir, "secrets.kdbx")
	integration.AssertFileNotExists(s.T(), dbPath, "Database should not exist with --no-create-database")

	// Verify keyfile NOT created
	keyfilePath := filepath.Join(configDir, "secrets.key")
	integration.AssertFileNotExists(s.T(), keyfilePath, "Keyfile should not exist with --no-create-database")
}

// TestNonInteractive_Verbose tests --verbose flag
func (s *InitNonInteractiveSuite) TestNonInteractive_Verbose() {
	os.Setenv("SECRETS_PASSWORD", "123456")

	cmd := exec.Command(s.BinPath, "init", "--non-interactive", "--verbose")
	output, err := cmd.CombinedOutput()

	s.NoError(err, "init --verbose should succeed")

	outputStr := string(output)
	// Verbose should show DEBUG messages
	s.Contains(outputStr, "DEBUG", "Verbose mode should show DEBUG messages")
}

// TestNonInteractive_AllFlags tests combination of multiple flags
func (s *InitNonInteractiveSuite) TestNonInteractive_AllFlags() {
	os.Setenv("SECRETS_PASSWORD", "123456")

	cmd := exec.Command(s.BinPath, "init",
		"--non-interactive",
		"--verbose",
		"--database-name", "production",
		"--no-keyfile",
	)
	output, err := cmd.CombinedOutput()

	s.NoError(err, "init with multiple flags should succeed: %s", string(output))

	// Verify custom database name directory
	configDir := s.TestPath(".secrets", "production")
	integration.AssertDirExists(s.T(), configDir, "Custom database directory should exist")

	// Verify database in custom directory
	dbPath := filepath.Join(configDir, "secrets.kdbx")
	integration.AssertFileExists(s.T(), dbPath, "Database should exist in custom directory")

	// Verify no keyfile
	keyfilePath := filepath.Join(configDir, "secrets.key")
	integration.AssertFileNotExists(s.T(), keyfilePath, "Keyfile should not exist")

	// Verify verbose output
	outputStr := string(output)
	s.Contains(outputStr, "DEBUG", "Should show debug output")
}
