package keepass_test

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/keepass"
)

func TestGroupCreationFromSecretsYaml(t *testing.T) {
	t.Log("\n=== GROUP CREATION FROM SECRETS.YAML TEST ===")
	
	// Create temporary directory for test
	tempDir := t.TempDir()
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	
	// Change to temp directory
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}
	
	// Create test secrets.yaml with profile
	secretsYaml := `metadata:
  profile: "test_profile"
  default_environment: "development"
---
development:
  - name: TEST_VAR
    entry: "/TEST_ENTRY"
    key: "test_key"
    type: "envvar"`
	
	if err := os.WriteFile("secrets.yaml", []byte(secretsYaml), 0644); err != nil {
		t.Fatalf("Failed to create test secrets.yaml: %v", err)
	}
	
	// Create test database paths
	dbPath := filepath.Join(tempDir, "test.kdbx")
	
	// Generate a random password for the test (NEVER hardcode passwords!)
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		t.Fatalf("Failed to generate random password: %v", err)
	}
	password := hex.EncodeToString(randomBytes)
	
	// Create KeePass database instance
	kp, err := keepass.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create KeePass instance: %v", err)
	}
	
	// Create database
	if err := kp.CreateDB("admin", password, false); err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	
	// Create the profile group directly (no entries)
	if err := kp.CreateGroup("test_profile"); err != nil {
		t.Fatalf("Failed to create profile group: %v", err)
	}
	
	// Save database
	if err := kp.Save(); err != nil {
		t.Fatalf("Failed to save database: %v", err)
	}
	
	// Close and reopen to verify persistence
	kp.Close()
	
	// Reopen database to verify the group was created
	newKp, err := keepass.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create new KeePass instance: %v", err)
	}
	
	// Open database with password only (no keyfile)
	if err := newKp.Open("admin", password, ""); err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	
	// List all entries to see the structure
	entries, err := newKp.List()
	if err != nil {
		t.Fatalf("Failed to list entries: %v", err)
	}
	
	t.Logf("Entries found in database: %v", entries)
	
	// Verify that we can write to the profile group
	testEntryPath := "/test_profile/test_entry"
	if err := newKp.Write(testEntryPath, "test_field", "test_value", false); err != nil {
		t.Fatalf("Failed to write to profile group: %v", err)
	}
	
	// Verify we can read from the profile group
	value, err := newKp.Get(testEntryPath, stringPtr("test_field"), nil)
	if err != nil {
		t.Fatalf("Failed to read from profile group: %v", err)
	}
	
	if value != "test_value" {
		t.Errorf("Expected 'test_value', got '%v'", value)
	}
	
	// List entries again to confirm the structure
	entriesAfter, err := newKp.List()
	if err != nil {
		t.Fatalf("Failed to list entries after write: %v", err)
	}
	
	t.Logf("Entries after write: %v", entriesAfter)
	
	// Verify the test entry is in the correct profile path
	found := false
	for _, entry := range entriesAfter {
		if strings.Contains(entry, "/test_profile/test_entry") {
			found = true
			break
		}
	}
	
	if !found {
		t.Errorf("Test entry not found in profile group. Entries: %v", entriesAfter)
	}
	
	// Clean up
	newKp.Close()
	
	t.Log("Group creation from secrets.yaml: PASS")
}

// Helper function to create string pointer
func stringPtr(s string) *string {
	return &s
}