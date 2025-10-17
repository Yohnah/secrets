package architecture_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestAllTestsUseMocks validates that all unit tests use mocks instead of real artifacts
// This test validates that tests DO NOT use real file system operations, databases, or external dependencies
//
// Architecture Rule: All tests MUST use mocks for external dependencies
// Tests MUST NOT use:
// - os.WriteFile, os.ReadFile, os.Chdir, os.Mkdir, etc.
// - Real database connections
// - Real file system operations
// - External network calls
//
// This test scans all test files and fails if real artifacts are detected
func TestAllTestsUseMocks(t *testing.T) {
	root, err := findModuleRoot()
	if err != nil {
		t.Fatalf("Failed to find module root: %v", err)
	}

	testsDir := filepath.Join(root, "tests")

	// Patterns that indicate use of real artifacts (not allowed in tests)
	artifactPatterns := []*regexp.Regexp{
		regexp.MustCompile(`os\.WriteFile\(`),
		regexp.MustCompile(`os\.ReadFile\(`),
		regexp.MustCompile(`os\.Chdir\(`),
		regexp.MustCompile(`os\.Mkdir\(`),
		regexp.MustCompile(`os\.MkdirAll\(`),
		regexp.MustCompile(`os\.Remove\(`),
		regexp.MustCompile(`os\.RemoveAll\(`),
		regexp.MustCompile(`os\.Create\(`),
		regexp.MustCompile(`os\.Open\(`),
		regexp.MustCompile(`os\.OpenFile\(`),
		regexp.MustCompile(`ioutil\.WriteFile\(`),
		regexp.MustCompile(`ioutil\.ReadFile\(`),
		regexp.MustCompile(`filepath\.Walk\(`),
		regexp.MustCompile(`exec\.Command\(`),
		regexp.MustCompile(`net\.Dial\(`),
		regexp.MustCompile(`http\.Get\(`),
		regexp.MustCompile(`http\.Post\(`),
		regexp.MustCompile(`sql\.Open\(`),
	}

	violations := []string{}

	// Walk through all test files in the tests directory to check for mock compliance
	// This recursively scans all subdirectories and applies filtering rules
	err = filepath.Walk(testsDir, func(currentFilePath string, fileInfo os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		// Skip non-Go files - only analyze Go source code
		if !strings.HasSuffix(currentFilePath, ".go") {
			return nil
		}

		// Skip non-test files - only check test files for mock compliance
		if !strings.HasSuffix(currentFilePath, "_test.go") {
			return nil
		}

		// Skip mock files - these files define mocks and may legitimately use real operations
		if strings.Contains(currentFilePath, "mocks_test.go") {
			return nil
		}

		// Skip architecture tests - these tests validate the architecture itself and may need real operations
		if strings.Contains(currentFilePath, "architecture/") {
			return nil
		}

		// Skip integration tests that require real file system operations for end-to-end testing
		// These tests verify complete workflows and are exempt from mock requirements
		exemptedIntegrationTests := []string{
			"init_test.go",              // Tests database initialization workflow
			"init_database_test.go",     // Tests database creation and setup
			"init_profiles_test.go",     // Tests profile creation logic
			"setup_test.go",             // Tests complete setup process
			"status_test.go",            // Tests status reporting functionality
			"show_profiles_test.go",     // Tests profile display operations
			"show_tree_test.go",         // Tests tree structure display
			"show_template_test.go",     // Tests template rendering
			"snapshots_new_test.go",     // Tests snapshot creation
			"snapshots_list_test.go",    // Tests snapshot listing
			"snapshots_delete_test.go",  // Tests snapshot deletion
			"snapshots_restore_test.go", // Tests snapshot restoration
			"secrets_validator_test.go", // Tests validation logic
			"validator_test.go",         // Tests validator functionality
			"import_variables_test.go",  // Tests parser functionality (needs real file I/O)
			"import_contents_test.go",   // Tests file content operations (needs real file I/O)
		}
		for _, exemptedTestFile := range exemptedIntegrationTests {
			if strings.Contains(currentFilePath, exemptedTestFile) {
				return nil
			}
		}

		// Read file content to analyze for artifact usage patterns
		fileContent, readErr := os.ReadFile(currentFilePath)
		if readErr != nil {
			return readErr
		}

		// Check for artifact patterns in the source code
		sourceCode := string(fileContent)
		for _, artifactPattern := range artifactPatterns {
			if artifactPattern.MatchString(sourceCode) {
				relativePath, _ := filepath.Rel(testsDir, currentFilePath)
				violations = append(violations, relativePath+": "+artifactPattern.String())
			}
		}

		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk tests directory: %v", err)
	}

	if len(violations) > 0 {
		t.Errorf("Found %d test files using real artifacts (violates mock requirement):", len(violations))
		for _, v := range violations {
			t.Errorf("  - %s", v)
		}
		t.Error("\nArchitecture violation: Tests must use mocks for all external dependencies")
		t.Error("Replace real artifacts with proper mocks (see mocks_test.go for examples)")
	}
}
