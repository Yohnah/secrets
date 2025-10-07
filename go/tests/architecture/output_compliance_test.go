package architecture_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestOutputManagerIsUsedForAllOutput ensures that all output goes through OutputManager
// This test validates that fmt.Print* is NOT used in business logic and CLI directories
//
// Architecture Rule: All structured output MUST go through OutputManager
// Only OutputManager, PromptManager, and LoggerManager can use fmt.Print* directly
// Business logic (internal/secrets) and CLI handlers (internal/cli) MUST use OutputManager
//
// This test scans critical directories (cli, secrets) and fails if fmt.Print* is found
func TestOutputManagerIsUsedForAllOutput(t *testing.T) {
	// Directories to scan - these MUST NOT use fmt.Print* directly
	scanDirs := []string{
		"../../internal/cli",
		"../../internal/secrets",
	}

	// Pattern to detect fmt.Print, fmt.Println, fmt.Printf
	printPattern := regexp.MustCompile(`fmt\.(Print|Println|Printf)\(`)

	violations := []string{}

	for _, dir := range scanDirs {
		absDir, err := filepath.Abs(dir)
		if err != nil {
			t.Fatalf("Failed to get absolute path for %s: %v", dir, err)
		}

		err = filepath.Walk(absDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Skip non-Go files
			if !strings.HasSuffix(path, ".go") {
				return nil
			}

			// Skip test files
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}

			// Read file content
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			// Check if file uses fmt.Print*
			if printPattern.Match(content) {
				relPath, _ := filepath.Rel(absDir, path)
				violations = append(violations, relPath)
			}

			return nil
		})

		if err != nil {
			t.Fatalf("Failed to walk directory %s: %v", dir, err)
		}
	}

	if len(violations) > 0 {
		t.Errorf("Found %d file(s) with fmt.Print* violations in business logic/CLI:", len(violations))
		for _, v := range violations {
			t.Errorf("  - %s", v)
		}
		t.Error("\nArchitecture violation: Business logic and CLI must use OutputManager")
		t.Error("Only OutputManager, PromptManager, and LoggerManager can use fmt.Print*")
	}
}
