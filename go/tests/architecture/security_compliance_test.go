package architecture_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoHardcodedPasswords ensures no hardcoded passwords in source code
func TestNoHardcodedPasswords(t *testing.T) {
	root, err := findModuleRoot()
	if err != nil {
		t.Fatalf("Failed to find module root: %v", err)
	}

	var violations []string

	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip test files and vendor directories
		if strings.HasSuffix(path, "_test.go") || strings.Contains(path, "/vendor/") {
			return nil
		}

		// Only check .go files
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		fileContent := string(content)
		lines := strings.Split(fileContent, "\n")

		for i, line := range lines {
			trimmed := strings.TrimSpace(line)

			// Skip comments
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
				continue
			}

			// Check for hardcoded password assignments - more specific patterns
			// Look for variable assignments with quoted strings that look like passwords
			if strings.Contains(line, "password") &&
				strings.Contains(line, ":=") &&
				strings.Contains(line, `"`) &&
				!strings.Contains(line, "os.Getenv") &&
				!strings.Contains(line, "config.GetPassword") &&
				!strings.Contains(line, "PromptPassword") &&
				!strings.Contains(line, "SECRETS_YOHNAH_PASSWORD") &&
				!strings.Contains(line, "TestPassword") && // Allow test passwords
				!strings.Contains(line, "testpassword") { // Allow test passwords
				violations = append(violations, filepath.Base(path)+":"+string(rune(i+1))+": "+strings.TrimSpace(line))
			}
		}

		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk directory: %v", err)
	}

	if len(violations) > 0 {
		t.Errorf("Found potential hardcoded passwords in:\n%s", strings.Join(violations, "\n"))
	}
}

// TestFilePermissionsSecurity ensures sensitive files use 0600
func TestFilePermissionsSecurity(t *testing.T) {
	root, err := findModuleRoot()
	if err != nil {
		t.Fatalf("Failed to find module root: %v", err)
	}

	var violations []string

	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip test files and vendor
		if strings.HasSuffix(path, "_test.go") || strings.Contains(path, "/vendor/") {
			return nil
		}

		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		fileContent := string(content)
		lines := strings.Split(fileContent, "\n")

		for i, line := range lines {
			// Check os.WriteFile calls
			if strings.Contains(line, "os.WriteFile") {
				// Check for sensitive files
				if strings.Contains(line, ".kdbx") ||
					strings.Contains(line, ".key") ||
					strings.Contains(line, "config.yml") ||
					strings.Contains(line, "keyfilePath") ||
					strings.Contains(line, "keyData") {
					// Must use 0600
					if !strings.Contains(line, "0600") {
						violations = append(violations, filepath.Base(path)+":"+string(rune(i+1)))
					}
				}
			}

			// Check os.OpenFile calls
			if strings.Contains(line, "os.OpenFile") {
				if strings.Contains(line, ".kdbx") || strings.Contains(line, "dbPath") {
					if !strings.Contains(line, "0600") {
						violations = append(violations, filepath.Base(path)+":"+string(rune(i+1)))
					}
				}
			}
		}

		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk directory: %v", err)
	}

	if len(violations) > 0 {
		t.Errorf("Found files with insecure permissions:\n%s", strings.Join(violations, "\n"))
	}
}

// TestNoSensitiveDataInLogs ensures passwords are not logged
func TestNoSensitiveDataInLogs(t *testing.T) {
	root, err := findModuleRoot()
	if err != nil {
		t.Fatalf("Failed to find module root: %v", err)
	}

	var violations []string

	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip test files and vendor
		if strings.HasSuffix(path, "_test.go") || strings.Contains(path, "/vendor/") {
			return nil
		}

		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		fileContent := string(content)
		lines := strings.Split(fileContent, "\n")

		for i, line := range lines {
			// Check logging calls
			if strings.Contains(line, "logger.") ||
				strings.Contains(line, "log.") ||
				strings.Contains(line, "fmt.Printf") ||
				strings.Contains(line, "fmt.Sprintf") {

				// Check if password variables are logged
				if (strings.Contains(line, "password") ||
					strings.Contains(line, "Password") ||
					strings.Contains(line, "securePassword") ||
					strings.Contains(line, "keyData")) &&
					!strings.Contains(line, "PromptPassword") &&
					!strings.Contains(line, "GetPassword") &&
					!strings.Contains(line, "//") {

					// Check if value is printed
					if strings.Contains(line, `"%s"`) ||
						strings.Contains(line, `"%v"`) ||
						strings.Contains(line, "String()") {
						violations = append(violations, filepath.Base(path)+":"+string(rune(i+1)))
					}
				}
			}
		}

		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk directory: %v", err)
	}

	if len(violations) > 0 {
		t.Errorf("Found potential sensitive data logging:\n%s", strings.Join(violations, "\n"))
	}
}
