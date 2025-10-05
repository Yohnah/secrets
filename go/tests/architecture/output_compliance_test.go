package architecture_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestOutputManagerIsUsedForAllOutput ensures that all output goes through OutputManager
// This test validates that fmt.Print* is only used in allowed locations
//
// Architecture Rule: All structured output MUST go through OutputManager
// Whitelist (allowed to use fmt.Print* directly):
//   - OutputManager: Implements output functionality
//   - PromptManager: Responsible for user interaction/prompts
//   - LoggerManager: Responsible for progress/log messages
//
// This test scans critical directories (cli, secrets) to prevent violations
// in business logic and command handlers.
func TestOutputManagerIsUsedForAllOutput(t *testing.T) {
	// Define allowed packages where fmt.Print* is acceptable
	allowedPackages := map[string]bool{
		"prompt": true, // PromptManager: user interaction
		"output": true, // OutputManager: implements output
		"logger": true, // LoggerManager: progress/log messages
	}

	// Directories to scan
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
				// Get package name from directory
				packageDir := filepath.Dir(path)
				packageName := filepath.Base(packageDir)

				// Check if this package is allowed
				if !allowedPackages[packageName] {
					relPath, _ := filepath.Rel(absDir, path)
					violations = append(violations, relPath)
				}
			}

			return nil
		})

		if err != nil {
			t.Fatalf("Failed to walk directory %s: %v", dir, err)
		}
	}

	if len(violations) > 0 {
		t.Errorf("Found %d file(s) with fmt.Print* violations:\n", len(violations))
		for _, v := range violations {
			t.Errorf("  - %s", v)
		}
		t.Error("\nArchitecture violation: All output must go through OutputManager")
		t.Error("Only PromptManager and OutputManager itself can use fmt.Print*")
		t.Error("Business logic and CLI should use OutputManager.OutputRaw() instead")
	}
}
