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

	err = filepath.Walk(testsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip non-Go files
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		// Skip non-test files
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}

		// Skip mock files (they may need to use some real operations)
		if strings.Contains(path, "mocks_test.go") {
			return nil
		}

		// Skip architecture tests (they test the architecture and may need real operations)
		if strings.Contains(path, "architecture/") {
			return nil
		}

		// Skip integration tests that need real file system operations
		// These tests verify end-to-end functionality and are allowed to use real artifacts
		integrationTests := []string{
			"init_test.go",
			"init_database_test.go",
			"init_profiles_test.go",
			"status_test.go",
			"show_profiles_test.go",
			"show_tree_test.go",
			"show_template_test.go",
			"snapshots_new_test.go",
			"snapshots_list_test.go",
			"snapshots_delete_test.go",
			"snapshots_restore_test.go",
			"secrets_validator_test.go",
			"validator_test.go",
		}
		for _, integrationTest := range integrationTests {
			if strings.Contains(path, integrationTest) {
				return nil
			}
		}

		// Read file content
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Check for artifact patterns in the source
		source := string(content)
		for _, pattern := range artifactPatterns {
			if pattern.MatchString(source) {
				relPath, _ := filepath.Rel(testsDir, path)
				violations = append(violations, relPath+": "+pattern.String())
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
