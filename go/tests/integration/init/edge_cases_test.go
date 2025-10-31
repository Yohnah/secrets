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

// InitEdgeCasesSuite tests edge cases for init command
type InitEdgeCasesSuite struct {
	integration.IntegrationSuite
}

// TestInitEdgeCasesSuite runs the edge cases test suite
func TestInitEdgeCasesSuite(t *testing.T) {
	suite.Run(t, new(InitEdgeCasesSuite))
}

// TestEdge_DatabaseAlreadyExists tests init when database already exists
func (s *InitEdgeCasesSuite) TestEdge_DatabaseAlreadyExists() {
	os.Setenv("SECRETS_PASSWORD", "123456")

	// First init
	cmd := exec.Command(s.BinPath, "init", "--non-interactive")
	_, err := cmd.CombinedOutput()
	s.NoError(err, "First init should succeed")

	// Second init without --force-recreate should fail or warn
	cmd = exec.Command(s.BinPath, "init", "--non-interactive")
	output, err := cmd.CombinedOutput()

	outputStr := string(output)
	// Should either fail or warn about existing database
	if err == nil {
		s.Contains(outputStr, "already exists", "Should warn about existing database")
	}
}

// TestEdge_InvalidDatabaseName tests invalid database name
func (s *InitEdgeCasesSuite) TestEdge_InvalidDatabaseName() {
	os.Setenv("SECRETS_PASSWORD", "123456")

	cmd := exec.Command(s.BinPath, "init",
		"--non-interactive",
		"--database-name", "invalid/name",
	)
	output, err := cmd.CombinedOutput()

	s.Error(err, "init with invalid database name should fail")

	outputStr := string(output)
	// El mensaje de validación menciona "alphanumeric" o "must be"
	s.True(len(outputStr) > 0 && (strings.Contains(outputStr, "alphanumeric") || strings.Contains(outputStr, "must be")), "Error should mention validation rule")
}

// TestEdge_PermissionDenied tests init with insufficient permissions
func (s *InitEdgeCasesSuite) TestEdge_PermissionDenied() {
	os.Setenv("SECRETS_PASSWORD", "123456")

	// Create a read-only directory
	readOnlyDir := s.TestPath("readonly")
	err := os.MkdirAll(readOnlyDir, 0555)
	s.NoError(err, "Should create read-only directory")

	dbPath := filepath.Join(readOnlyDir, "test.kdbx")

	cmd := exec.Command(s.BinPath, "init",
		"--non-interactive",
		"--database-path", dbPath,
	)
	output, err := cmd.CombinedOutput()

	// Should fail due to permission denied
	s.Error(err, "init in read-only directory should fail")

	outputStr := string(output)
	s.True(len(outputStr) > 0, "Should output error message")
}

// TestEdge_EnvVarPrecedence tests environment variable precedence
func (s *InitEdgeCasesSuite) TestEdge_EnvVarPrecedence() {
	os.Setenv("SECRETS_PASSWORD", "123456")
	os.Setenv("SECRETS_DATABASE", s.TestPath("env-db.kdbx"))
	os.Setenv("SECRETS_KEYFILE", s.TestPath("env-key.key"))

	// Flag should override env var
	flagDB := s.TestPath("flag-db.kdbx")

	cmd := exec.Command(s.BinPath, "init",
		"--non-interactive",
		"--database-path", flagDB,
	)
	output, err := cmd.CombinedOutput()

	s.NoError(err, "init with flag override should succeed: %s", string(output))

	// Verify flag path was used (not env var)
	integration.AssertFileExists(s.T(), flagDB, "Database should exist at flag path")

	// Env var path should NOT exist
	envDB := s.TestPath("env-db.kdbx")
	integration.AssertFileNotExists(s.T(), envDB, "Database should not exist at env var path")
}
