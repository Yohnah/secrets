package architecture_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yohnah/secrets/tests/testutils"
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
				relPath, _ := filepath.Rel(root, path)
				violations = append(violations, testutils.NormalizePath(relPath)+":"+string(rune(i+1))+": "+strings.TrimSpace(line))
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
						relPath, _ := filepath.Rel(root, path)
						violations = append(violations, testutils.NormalizePath(relPath)+":"+string(rune(i+1)))
					}
				}
			}

			// Check os.OpenFile calls
			if strings.Contains(line, "os.OpenFile") {
				if strings.Contains(line, ".kdbx") || strings.Contains(line, "dbPath") {
					if !strings.Contains(line, "0600") {
						relPath, _ := filepath.Rel(root, path)
						violations = append(violations, testutils.NormalizePath(relPath)+":"+string(rune(i+1)))
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
						relPath, _ := filepath.Rel(root, path)
						violations = append(violations, testutils.NormalizePath(relPath)+":"+string(rune(i+1)))
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

// TestCryptoRandUsage validates that crypto/rand is used instead of math/rand
func TestCryptoRandUsage(t *testing.T) {
	root, err := findModuleRoot()
	if err != nil {
		t.Fatalf("Failed to find module root: %v", err)
	}

	var violations []string
	mathRandUsed := false
	cryptoRandUsed := false

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
			// Check for math/rand import
			if strings.Contains(line, `"math/rand"`) && !strings.HasPrefix(strings.TrimSpace(line), "//") {
				mathRandUsed = true
				relPath, _ := filepath.Rel(root, path)
				violations = append(violations, testutils.NormalizePath(relPath)+":"+string(rune(i+1))+": uses math/rand instead of crypto/rand")
			}

			// Check for crypto/rand usage
			if strings.Contains(line, `"crypto/rand"`) || strings.Contains(line, "rand.Read") {
				cryptoRandUsed = true
			}
		}

		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk directory: %v", err)
	}

	if mathRandUsed {
		t.Errorf("SECURITY VIOLATION: math/rand is used. Must use crypto/rand for security:\n%s", strings.Join(violations, "\n"))
	}

	if !cryptoRandUsed {
		t.Errorf("WARNING: crypto/rand is not used anywhere in the codebase")
	}
}

// TestPasswordMemoryCleanup validates that passwords are properly cleared from memory
func TestPasswordMemoryCleanup(t *testing.T) {
	root, err := findModuleRoot()
	if err != nil {
		t.Fatalf("Failed to find module root: %v", err)
	}

	var violations []string
	clearMethodFound := false

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
			// Look for Clear() method implementations
			if strings.Contains(line, "func") && strings.Contains(line, "Clear()") {
				clearMethodFound = true
			}

			// Check for password variables without defer Clear()
			if strings.Contains(line, "securePassword") && strings.Contains(line, ":=") {
				// Look ahead for defer Clear() call
				foundDefer := false
				for j := i; j < len(lines) && j < i+10; j++ {
					if strings.Contains(lines[j], "defer") && strings.Contains(lines[j], ".Clear()") {
						foundDefer = true
						break
					}
				}
				if !foundDefer && !strings.Contains(path, "types") {
					relPath, _ := filepath.Rel(root, path)
					violations = append(violations, testutils.NormalizePath(relPath)+":"+string(rune(i+1))+": securePassword without defer Clear()")
				}
			}
		}

		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk directory: %v", err)
	}

	if !clearMethodFound {
		t.Errorf("WARNING: No Clear() methods found for memory cleanup")
	}

	if len(violations) > 0 {
		t.Logf("INFO: Potential missing defer Clear() calls (may be false positives):\n%s", strings.Join(violations, "\n"))
	}
}

// TestPathTraversalPrevention validates that path sanitization is implemented
func TestPathTraversalPrevention(t *testing.T) {
	root, err := findModuleRoot()
	if err != nil {
		t.Fatalf("Failed to find module root: %v", err)
	}

	sanitizePathFound := false
	evalSymlinksUsed := false

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

		// Look for sanitizePath function
		if strings.Contains(fileContent, "func sanitizePath") {
			sanitizePathFound = true
		}

		// Look for EvalSymlinks usage
		if strings.Contains(fileContent, "filepath.EvalSymlinks") {
			evalSymlinksUsed = true
		}

		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk directory: %v", err)
	}

	if !sanitizePathFound {
		t.Errorf("SECURITY VIOLATION: No sanitizePath function found - path traversal attacks possible")
	}

	if !evalSymlinksUsed {
		t.Errorf("SECURITY VIOLATION: filepath.EvalSymlinks not used - symlink attacks possible")
	}
}

// TestErrorMessageSanitization validates that sensitive data is not leaked in errors
func TestErrorMessageSanitization(t *testing.T) {
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
			// Check for error messages that might contain sensitive data
			if strings.Contains(line, "fmt.Errorf") || strings.Contains(line, "errors.New") {
				// Look for SecureValue.String() or SecurePassword.String() in error messages
				if strings.Contains(line, ".String()") {
					// Check if it's a secure type
					if strings.Contains(line, "securePassword") ||
						strings.Contains(line, "secureValue") ||
						strings.Contains(line, "password.String()") {
						relPath, _ := filepath.Rel(root, path)
						violations = append(violations, testutils.NormalizePath(relPath)+":"+string(rune(i+1))+": Sensitive data in error message")
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
		t.Errorf("SECURITY VIOLATION: Sensitive data may be leaked in error messages:\n%s", strings.Join(violations, "\n"))
	}
}

// TestCentralizedPasswordAccess validates that password access is centralized
func TestCentralizedPasswordAccess(t *testing.T) {
	root, err := findModuleRoot()
	if err != nil {
		t.Fatalf("Failed to find module root: %v", err)
	}

	var violations []string
	getPasswordMethodFound := false

	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip test files, vendor, and config manager itself
		if strings.HasSuffix(path, "_test.go") ||
			strings.Contains(path, "/vendor/") ||
			strings.Contains(path, "/config/manager.go") {
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

		// Check for GetPassword method
		if strings.Contains(fileContent, "func") && strings.Contains(fileContent, "GetPassword()") {
			getPasswordMethodFound = true
		}

		for i, line := range lines {
			// Check for direct os.Getenv("SECRETS_YOHNAH_PASSWORD") usage
			if strings.Contains(line, `os.Getenv("SECRETS_YOHNAH_PASSWORD")`) {
				// Make sure it's not in config manager or helpers
				if !testutils.ContainsPath(path, "/config/") && !testutils.ContainsPath(path, "/common/helpers.go") {
					relPath, _ := filepath.Rel(root, path)
					violations = append(violations, testutils.NormalizePath(relPath)+":"+string(rune(i+1))+": Direct password env access")
				}
			}
		}

		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk directory: %v", err)
	}

	if !getPasswordMethodFound {
		t.Errorf("WARNING: GetPassword() method not found - password access may not be centralized")
	}

	if len(violations) > 0 {
		t.Errorf("SECURITY VIOLATION: Direct password environment variable access found:\n%s", strings.Join(violations, "\n"))
	}
}
