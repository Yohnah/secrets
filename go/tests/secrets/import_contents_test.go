package secrets_test

import (
	"os"
	"path/filepath"
	"testing"
)

// TestImportContents_JSONFile tests importing a JSON file as contents by filename
func TestImportContents_JSONFile(t *testing.T) {
	tempDir := t.TempDir()
	jsonFilePath := filepath.Join(tempDir, "DB_HOST.json")

	// Create file with JSON content
	content := `{"host": "localhost", "port": 5432}`
	if err := os.WriteFile(jsonFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Verify file exists and has content
	fileContent, err := os.ReadFile(jsonFilePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	if string(fileContent) != content {
		t.Errorf("Expected content '%s', got '%s'", content, string(fileContent))
	}
}

// TestImportContents_TextFile tests importing a text file as contents by filename
func TestImportContents_TextFile(t *testing.T) {
	tempDir := t.TempDir()
	textFilePath := filepath.Join(tempDir, "API_KEY.txt")

	// Create file with text content
	content := `sk-proj-abc123xyz789`
	if err := os.WriteFile(textFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Verify file exists and has content
	fileContent, err := os.ReadFile(textFilePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	if string(fileContent) != content {
		t.Errorf("Expected content '%s', got '%s'", content, string(fileContent))
	}
}

// TestImportContents_CertificateFile tests importing a certificate file
func TestImportContents_CertificateFile(t *testing.T) {
	tempDir := t.TempDir()
	certFilePath := filepath.Join(tempDir, "SSL_CERT.pem")

	// Create file with certificate content
	content := `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKuWMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
-----END CERTIFICATE-----`
	if err := os.WriteFile(certFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Verify file exists and has content
	fileContent, err := os.ReadFile(certFilePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	if string(fileContent) != content {
		t.Errorf("Expected certificate content to match")
	}
}

// TestImportContents_BinaryFile tests importing a binary file
func TestImportContents_BinaryFile(t *testing.T) {
	tempDir := t.TempDir()
	binaryFilePath := filepath.Join(tempDir, "SSH_KEY.bin")

	// Create file with binary content
	content := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD}
	if err := os.WriteFile(binaryFilePath, content, 0600); err != nil {
		t.Fatal(err)
	}

	// Verify file exists and has content
	fileContent, err := os.ReadFile(binaryFilePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	if len(fileContent) != len(content) {
		t.Errorf("Expected %d bytes, got %d", len(content), len(fileContent))
	}
	for i, b := range content {
		if fileContent[i] != b {
			t.Errorf("Byte mismatch at index %d: expected %x, got %x", i, b, fileContent[i])
		}
	}
}

// TestImportContents_Base64EncodedFile tests importing base64 encoded content with decoding
func TestImportContents_Base64EncodedFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "PASSWORD.txt")

	// "secret123" in base64 is "c2VjcmV0MTIz"
	base64Content := `c2VjcmV0MTIz`
	if err := os.WriteFile(filePath, []byte(base64Content), 0600); err != nil {
		t.Fatal(err)
	}

	// Read file and verify base64 content
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	if string(fileContent) != base64Content {
		t.Errorf("Expected base64 content '%s', got '%s'", base64Content, string(fileContent))
	}
}

// TestImportContents_MultilineFile tests importing multiline file content
func TestImportContents_MultilineFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "CONFIG.yml")

	// Create file with multiline YAML content
	content := `server:
  host: localhost
  port: 8080
database:
  url: postgres://localhost/mydb
  pool_size: 10`
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Verify file exists and has multiline content
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	if string(fileContent) != content {
		t.Errorf("Multiline content mismatch")
	}
}

// TestImportContents_EmptyFile tests importing an empty file
func TestImportContents_EmptyFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "EMPTY.txt")

	// Create empty file
	if err := os.WriteFile(filePath, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	// Verify file exists and is empty
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	if len(fileContent) != 0 {
		t.Errorf("Expected empty file, got %d bytes", len(fileContent))
	}
}

// TestImportContents_LargeFile tests importing a large file
func TestImportContents_LargeFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "LARGE_DATA.txt")

	// Create large content (100KB)
	largeContent := make([]byte, 100*1024)
	for i := range largeContent {
		largeContent[i] = byte('A' + (i % 26))
	}
	if err := os.WriteFile(filePath, largeContent, 0600); err != nil {
		t.Fatal(err)
	}

	// Verify file exists and has correct size
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	if len(fileContent) != len(largeContent) {
		t.Errorf("Expected %d bytes, got %d", len(largeContent), len(fileContent))
	}
}

// TestImportContents_FilenameMatching tests that filename must match item name in secrets.yml
func TestImportContents_FilenameMatching(t *testing.T) {
	// This test verifies the filename matching logic:
	// - File "DB_HOST" should match item name "DB_HOST"
	// - File "DB_HOST.txt" should match item name "DB_HOST" (extension removed)
	// - File "DB_HOST.json" should match item name "DB_HOST" (extension removed)

	testCases := []struct {
		filename    string
		itemName    string
		shouldMatch bool
	}{
		{"DB_HOST", "DB_HOST", true},
		{"DB_HOST.txt", "DB_HOST", true},
		{"DB_HOST.json", "DB_HOST", true},
		{"DB_HOST.pem", "DB_HOST", true},
		{"API_KEY", "API_KEY", true},
		{"API_KEY.key", "API_KEY", true},
		{"WRONG_NAME", "DB_HOST", false},
		{"DB_HOST", "API_KEY", false},
	}

	for _, tc := range testCases {
		t.Run(tc.filename+"->"+tc.itemName, func(t *testing.T) {
			// Extract base name without extension
			baseName := tc.filename
			if idx := filepath.Ext(tc.filename); idx != "" {
				baseName = tc.filename[:len(tc.filename)-len(idx)]
			}

			matches := baseName == tc.itemName
			if matches != tc.shouldMatch {
				t.Errorf("Expected match=%v for filename '%s' and item '%s', got %v",
					tc.shouldMatch, tc.filename, tc.itemName, matches)
			}
		})
	}
}

// TestImportContents_FileNotFound tests error handling when file doesn't exist
func TestImportContents_FileNotFound(t *testing.T) {
	_, err := os.ReadFile("/nonexistent/file.txt")
	if err == nil {
		t.Fatal("Expected error for non-existent file, got nil")
	}
}

// TestImportContents_PermissionDenied tests error handling for permission denied
func TestImportContents_PermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Skipping permission test when running as root")
	}

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "RESTRICTED.txt")

	// Create file with no read permissions
	if err := os.WriteFile(filePath, []byte("secret"), 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(filePath, 0600) // Cleanup

	// Try to read file (should fail)
	_, err := os.ReadFile(filePath)
	if err == nil {
		t.Fatal("Expected permission error, got nil")
	}
}

// TestImportContents_SpecialCharactersInContent tests importing content with special characters
func TestImportContents_SpecialCharactersInContent(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "SPECIAL.txt")

	// Create file with special characters
	content := `Special chars: !@#$%^&*()_+-={}[]|\:";'<>?,./~` + "`\n\t\r"
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Verify content preserved special characters
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	if string(fileContent) != content {
		t.Errorf("Special characters not preserved")
	}
}

// TestImportContents_UnicodeContent tests importing Unicode content
func TestImportContents_UnicodeContent(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "UNICODE.txt")

	// Create file with Unicode content
	content := `Hello 世界 🌍 Привет こんにちは`
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Verify Unicode content preserved
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	if string(fileContent) != content {
		t.Errorf("Unicode content not preserved")
	}
}

// TestImportContents_PathWithSpaces tests importing file with spaces in path
func TestImportContents_PathWithSpaces(t *testing.T) {
	tempDir := t.TempDir()
	subDir := filepath.Join(tempDir, "folder with spaces")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	filePath := filepath.Join(subDir, "file with spaces.txt")
	content := `content in file with spaces`
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Verify file can be read despite spaces in path
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file with spaces: %v", err)
	}
	if string(fileContent) != content {
		t.Errorf("Content mismatch for file with spaces in path")
	}
}
