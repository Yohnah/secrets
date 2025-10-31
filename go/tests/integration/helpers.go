package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AssertFileExists checks if a file exists at the given path
func AssertFileExists(t *testing.T, path string, msgAndArgs ...interface{}) {
	info, err := os.Stat(path)
	require.NoError(t, err, msgAndArgs...)
	require.False(t, info.IsDir(), "Expected file, got directory: %s", path)
}

// AssertFileNotExists checks if a file does NOT exist at the given path
func AssertFileNotExists(t *testing.T, path string, msgAndArgs ...interface{}) {
	_, err := os.Stat(path)
	require.True(t, os.IsNotExist(err), "Expected file to not exist: %s", path)
}

// AssertDirExists checks if a directory exists at the given path
func AssertDirExists(t *testing.T, path string, msgAndArgs ...interface{}) {
	info, err := os.Stat(path)
	require.NoError(t, err, msgAndArgs...)
	require.True(t, info.IsDir(), "Expected directory, got file: %s", path)
}

// AssertDirNotExists checks if a directory does NOT exist at the given path
func AssertDirNotExists(t *testing.T, path string, msgAndArgs ...interface{}) {
	_, err := os.Stat(path)
	require.True(t, os.IsNotExist(err), "Expected directory to not exist: %s", path)
}

// AssertFilePermissions checks if a file has the expected permissions
func AssertFilePermissions(t *testing.T, path string, expectedMode os.FileMode, msgAndArgs ...interface{}) {
	info, err := os.Stat(path)
	require.NoError(t, err, msgAndArgs...)

	actualMode := info.Mode().Perm()
	assert.Equal(t, expectedMode, actualMode, "File permissions mismatch for %s", path)
}

// AssertFileContains checks if a file contains a specific string
func AssertFileContains(t *testing.T, path string, search string, msgAndArgs ...interface{}) {
	content, err := os.ReadFile(path)
	require.NoError(t, err, msgAndArgs...)

	assert.Contains(t, string(content), search, "File %s does not contain expected string", path)
}

// AssertFileNotContains checks if a file does NOT contain a specific string
func AssertFileNotContains(t *testing.T, path string, search string, msgAndArgs ...interface{}) {
	content, err := os.ReadFile(path)
	require.NoError(t, err, msgAndArgs...)

	assert.NotContains(t, string(content), search, "File %s contains unexpected string", path)
}

// AssertFileContainsAll checks if a file contains all specified strings
func AssertFileContainsAll(t *testing.T, path string, searches []string, msgAndArgs ...interface{}) {
	content, err := os.ReadFile(path)
	require.NoError(t, err, msgAndArgs...)

	for _, search := range searches {
		assert.Contains(t, string(content), search, "File %s does not contain expected string: %s", path, search)
	}
}

// AssertOutputContains checks if command output contains a specific string
func AssertOutputContains(t *testing.T, output string, search string, msgAndArgs ...interface{}) {
	assert.Contains(t, output, search, msgAndArgs...)
}

// AssertOutputNotContains checks if command output does NOT contain a specific string
func AssertOutputNotContains(t *testing.T, output string, search string, msgAndArgs ...interface{}) {
	assert.NotContains(t, output, search, msgAndArgs...)
}

// AssertExitCode checks if command exit code matches expected
func AssertExitCode(t *testing.T, err error, expectedCode int) {
	if expectedCode == 0 {
		assert.NoError(t, err, "Expected successful execution (exit code 0)")
	} else {
		assert.Error(t, err, "Expected command to fail with exit code %d", expectedCode)
	}
}

// CopyFixture copies a fixture file to the destination path
func CopyFixture(t *testing.T, fixturePath string, destPath string) {
	content, err := os.ReadFile(fixturePath)
	require.NoError(t, err, "Failed to read fixture file: %s", fixturePath)

	// Create parent directory if needed
	destDir := filepath.Dir(destPath)
	err = os.MkdirAll(destDir, 0755)
	require.NoError(t, err, "Failed to create destination directory: %s", destDir)

	err = os.WriteFile(destPath, content, 0644)
	require.NoError(t, err, "Failed to write fixture to: %s", destPath)
}

// CreateTempFile creates a temporary file with content in the test directory
func CreateTempFile(t *testing.T, dir string, filename string, content string) string {
	path := filepath.Join(dir, filename)
	err := os.WriteFile(path, []byte(content), 0644)
	require.NoError(t, err, "Failed to create temp file: %s", path)
	return path
}

// CreateTempDir creates a temporary directory in the test directory
func CreateTempDir(t *testing.T, baseDir string, dirname string) string {
	path := filepath.Join(baseDir, dirname)
	err := os.MkdirAll(path, 0755)
	require.NoError(t, err, "Failed to create temp directory: %s", path)
	return path
}

// NormalizeLineEndings normalizes line endings for cross-platform comparison
func NormalizeLineEndings(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}
