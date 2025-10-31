package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
)

// IntegrationSuite provides base setup for integration tests
type IntegrationSuite struct {
	suite.Suite
	TestRoot    string   // Temporary test directory
	BinPath     string   // Path to secrets binary
	OriginalEnv []string // Original environment variables
	OriginalDir string   // Original working directory
}

// SetupSuite runs once before all tests in the suite
func (s *IntegrationSuite) SetupSuite() {
	// Verify binary exists
	binPath := filepath.Join("/workspaces/secrets", "bin", "secrets")
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		s.T().Fatalf("Binary not found at %s. Run 'task build' first.", binPath)
	}
	s.BinPath = binPath

	// Store original working directory
	wd, err := os.Getwd()
	if err != nil {
		s.T().Fatalf("Failed to get working directory: %v", err)
	}
	s.OriginalDir = wd
}

// SetupTest runs before each test
func (s *IntegrationSuite) SetupTest() {
	// Create unique test directory
	testID := uuid.New().String()[:8]
	s.TestRoot = filepath.Join(os.TempDir(), "secrets-integration-test-"+testID)

	err := os.MkdirAll(s.TestRoot, 0700)
	if err != nil {
		s.T().Fatalf("Failed to create test directory: %v", err)
	}

	// Store original environment
	s.OriginalEnv = os.Environ()

	// Set HOME to test directory (isolate config)
	os.Setenv("HOME", s.TestRoot)

	// Clear secrets-related env vars
	os.Unsetenv("SECRETS_CONFIG_FILE")
	os.Unsetenv("SECRETS_DATABASE")
	os.Unsetenv("SECRETS_KEYFILE")
	os.Unsetenv("SECRETS_FILE")
	os.Unsetenv("SECRETS_PASSWORD")

	// Change to test directory
	err = os.Chdir(s.TestRoot)
	if err != nil {
		s.T().Fatalf("Failed to change to test directory: %v", err)
	}
}

// TearDownTest runs after each test
func (s *IntegrationSuite) TearDownTest() {
	// Restore original directory
	if s.OriginalDir != "" {
		os.Chdir(s.OriginalDir)
	}

	// Restore original environment
	os.Clearenv()
	for _, env := range s.OriginalEnv {
		pair := splitEnv(env)
		if len(pair) == 2 {
			os.Setenv(pair[0], pair[1])
		}
	}

	// Clean up test directory
	if s.TestRoot != "" {
		os.RemoveAll(s.TestRoot)
	}
}

// TestPath returns an absolute path within the test directory
func (s *IntegrationSuite) TestPath(parts ...string) string {
	allParts := append([]string{s.TestRoot}, parts...)
	return filepath.Join(allParts...)
}

// splitEnv splits an environment variable string into key and value
func splitEnv(env string) []string {
	for i := 0; i < len(env); i++ {
		if env[i] == '=' {
			return []string{env[:i], env[i+1:]}
		}
	}
	return []string{env}
}

// RunIntegrationTests is a helper to run test suites
func RunIntegrationTests(t *testing.T, testSuite suite.TestingSuite) {
	suite.Run(t, testSuite)
}
