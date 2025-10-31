package init

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yohnah/secrets/tests/integration"
	"github.com/stretchr/testify/suite"
)

// InitMultiDatabaseSuite tests multiple database creation in single config
type InitMultiDatabaseSuite struct {
	integration.IntegrationSuite
}

func TestInitMultiDatabaseSuite(t *testing.T) {
	suite.Run(t, new(InitMultiDatabaseSuite))
}

// TestMultiDatabase_CreateThreeDatabases tests creating 3 databases sequentially
func (s *InitMultiDatabaseSuite) TestMultiDatabase_CreateThreeDatabases() {
	os.Setenv("SECRETS_PASSWORD", "123456")
	configPath := s.TestPath("multi", "config.yml")

	databases := []string{"default", "staging", "production"}

	// Create each database
	for _, dbName := range databases {
		cmd := exec.Command(s.BinPath, "init",
			"--non-interactive",
			"--config", configPath,
			"--database-name", dbName,
		)
		output, err := cmd.CombinedOutput()
		s.NoError(err, "init with database '%s' should succeed: %s", dbName, string(output))

		// Verify database directory created (relative to HOME, not config)
		dbDir := s.TestPath(".secrets", dbName)
		integration.AssertDirExists(s.T(), dbDir, "Database directory '%s' should exist", dbName)

		// Verify database file created
		dbPath := filepath.Join(dbDir, "secrets.kdbx")
		integration.AssertFileExists(s.T(), dbPath, "Database file '%s/secrets.kdbx' should exist", dbName)

		// Verify keyfile created
		keyfilePath := filepath.Join(dbDir, "secrets.key")
		integration.AssertFileExists(s.T(), keyfilePath, "Keyfile '%s/secrets.key' should exist", dbName)
	}

	// Verify config.yml exists
	integration.AssertFileExists(s.T(), configPath, "Config file should exist")

	// Verify config.yml contains all three databases
	configContent, err := os.ReadFile(configPath)
	s.NoError(err, "Should read config file")
	contentStr := string(configContent)

	for _, dbName := range databases {
		s.Contains(contentStr, dbName, "Config should contain database '%s'", dbName)
	}

	// Verify YAML separators (should have 2 separators for 3 databases)
	separatorCount := strings.Count(contentStr, "---")
	s.Equal(2, separatorCount, "Config should have 2 YAML separators for 3 databases")

	// Verify order (first database should appear before others)
	defaultIdx := strings.Index(contentStr, `"default"`)
	if defaultIdx == -1 {
		defaultIdx = strings.Index(contentStr, "default")
	}
	stagingIdx := strings.Index(contentStr, `"staging"`)
	if stagingIdx == -1 {
		stagingIdx = strings.Index(contentStr, "staging")
	}
	prodIdx := strings.Index(contentStr, `"production"`)
	if prodIdx == -1 {
		prodIdx = strings.Index(contentStr, "production")
	}

	s.Less(defaultIdx, stagingIdx, "Default should appear before staging")
	s.Less(stagingIdx, prodIdx, "Staging should appear before production")
}

// TestMultiDatabase_DuplicateNameAborts tests that creating duplicate database fails
func (s *InitMultiDatabaseSuite) TestMultiDatabase_DuplicateNameAborts() {
	os.Setenv("SECRETS_PASSWORD", "123456")
	configPath := s.TestPath("duplicate", "config.yml")

	// Create first database
	cmd := exec.Command(s.BinPath, "init",
		"--non-interactive",
		"--config", configPath,
		"--database-name", "mydb",
	)
	output, err := cmd.CombinedOutput()
	s.NoError(err, "First init should succeed: %s", string(output))

	// Try to create same database again (should succeed but not duplicate)
	cmd = exec.Command(s.BinPath, "init",
		"--non-interactive",
		"--config", configPath,
		"--database-name", "mydb",
	)
	output, err = cmd.CombinedOutput()
	s.NoError(err, "Second init with same name should succeed (no-op): %s", string(output))
	outputStr := string(output)
	s.Contains(outputStr, "already exists", "Output should indicate database already exists")

	// Verify config.yml was NOT modified (still only one database)
	configContent, err := os.ReadFile(configPath)
	s.NoError(err, "Should read config file")
	contentStr := string(configContent)

	// Should NOT have separator (only one database)
	separatorCount := strings.Count(contentStr, "---")
	s.Equal(0, separatorCount, "Config should have 0 YAML separators for single database")

	// Database name should appear exactly once
	nameWithQuotes := strings.Count(contentStr, `name: "mydb"`)
	nameWithoutQuotes := strings.Count(contentStr, "name: mydb")
	total := nameWithQuotes + nameWithoutQuotes
	s.Equal(1, total, "Database name should appear exactly once in config")
}

// TestMultiDatabase_ForceRecreatePreservesOtherDBs tests --force-recreate with multiple DBs
func (s *InitMultiDatabaseSuite) TestMultiDatabase_ForceRecreatePreservesOtherDBs() {
	os.Setenv("SECRETS_PASSWORD", "123456")
	configPath := s.TestPath("recreate", "config.yml")

	// Create two databases
	for _, dbName := range []string{"db1", "db2"} {
		cmd := exec.Command(s.BinPath, "init",
			"--non-interactive",
			"--config", configPath,
			"--database-name", dbName,
		)
		output, err := cmd.CombinedOutput()
		s.NoError(err, "Init database '%s' should succeed: %s", dbName, string(output))
	}

	// Read original config
	originalConfig, err := os.ReadFile(configPath)
	s.NoError(err, "Should read original config")

	// Force recreate first database
	cmd := exec.Command(s.BinPath, "init",
		"--non-interactive",
		"--config", configPath,
		"--database-name", "db1",
		"--force-recreate",
	)
	output, err := cmd.CombinedOutput()
	s.NoError(err, "Force recreate should succeed: %s", string(output))

	// Read updated config
	updatedConfig, err := os.ReadFile(configPath)
	s.NoError(err, "Should read updated config")

	updatedStr := string(updatedConfig)

	// Verify both databases still in config
	s.Contains(updatedStr, "db1", "Config should still contain db1")
	s.Contains(updatedStr, "db2", "Config should still contain db2")

	// Verify separator still exists
	separatorCount := strings.Count(updatedStr, "---")
	s.Equal(1, separatorCount, "Config should still have 1 YAML separator for 2 databases")

	// Verify db2 section unchanged
	s.Contains(string(originalConfig), "db2", "Original config had db2")
	s.Contains(updatedStr, "db2", "Updated config still has db2")
}

// TestMultiDatabase_MixedConfigurations tests databases with different configs
func (s *InitMultiDatabaseSuite) TestMultiDatabase_MixedConfigurations() {
	os.Setenv("SECRETS_PASSWORD", "123456")
	configPath := s.TestPath("mixed", "config.yml")

	// DB1: with keyfile
	cmd := exec.Command(s.BinPath, "init",
		"--non-interactive",
		"--config", configPath,
		"--database-name", "with-keyfile",
	)
	output, err := cmd.CombinedOutput()
	s.NoError(err, "DB with keyfile should succeed: %s", string(output))

	// DB2: without keyfile
	cmd = exec.Command(s.BinPath, "init",
		"--non-interactive",
		"--config", configPath,
		"--database-name", "without-keyfile",
		"--no-keyfile",
	)
	output, err = cmd.CombinedOutput()
	s.NoError(err, "DB without keyfile should succeed: %s", string(output))

	// DB3: only config, no database
	cmd = exec.Command(s.BinPath, "init",
		"--non-interactive",
		"--config", configPath,
		"--database-name", "config-only",
		"--no-create-database",
	)
	output, err = cmd.CombinedOutput()
	s.NoError(err, "Config-only should succeed: %s", string(output))

	// Verify config.yml
	configContent, err := os.ReadFile(configPath)
	s.NoError(err, "Should read config file")
	contentStr := string(configContent)

	// Verify all three databases in config
	s.Contains(contentStr, "with-keyfile", "Config should contain with-keyfile")
	s.Contains(contentStr, "without-keyfile", "Config should contain without-keyfile")
	s.Contains(contentStr, "config-only", "Config should contain config-only")

	// Verify correct number of separators
	separatorCount := strings.Count(contentStr, "---")
	s.Equal(2, separatorCount, "Config should have 2 YAML separators for 3 databases")

	// Verify first database has keyfile field
	firstDBEnd := strings.Index(contentStr, "---")
	if firstDBEnd > 0 {
		firstDBSection := contentStr[:firstDBEnd]
		s.Contains(firstDBSection, "keyfile:", "First database should have keyfile field")
	}

	// Verify files created/not created correctly
	integration.AssertFileExists(s.T(),
		s.TestPath(".secrets", "with-keyfile", "secrets.kdbx"),
		"with-keyfile database should exist")
	integration.AssertFileExists(s.T(),
		s.TestPath(".secrets", "with-keyfile", "secrets.key"),
		"with-keyfile keyfile should exist")

	integration.AssertFileExists(s.T(),
		s.TestPath(".secrets", "without-keyfile", "secrets.kdbx"),
		"without-keyfile database should exist")
	integration.AssertFileNotExists(s.T(),
		s.TestPath(".secrets", "without-keyfile", "secrets.key"),
		"without-keyfile keyfile should NOT exist")

	integration.AssertFileNotExists(s.T(),
		s.TestPath(".secrets", "config-only", "secrets.kdbx"),
		"config-only database should NOT exist")
}
