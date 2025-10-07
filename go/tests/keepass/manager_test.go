package keepass_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/keepass"
)

func TestCreateEntry(t *testing.T) {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "keepass_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Setup test files
	dbPath := filepath.Join(tempDir, "test.kdbx")
	keyfilePath := filepath.Join(tempDir, "test.key")
	password := "testpassword"

	// Create KeePass manager
	kpMgr := keepass.NewManager()

	// Generate keyfile first
	err = kpMgr.GenerateKeyfile(keyfilePath)
	if err != nil {
		t.Fatalf("Failed to generate keyfile: %v", err)
	}

	// Create database with profile and environment structure
	err = kpMgr.CreateDatabase(dbPath, keyfilePath, password, "TestDB")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	profileName := "testprofile"
	err = kpMgr.CreateProfile(dbPath, keyfilePath, password, profileName)
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	envName := "testenv"
	err = kpMgr.CreateGroup(dbPath, keyfilePath, password, profileName, "HEAD", envName)
	if err != nil {
		t.Fatalf("Failed to create environment group: %v", err)
	}

	tests := []struct {
		name        string
		entryPath   string
		expectError bool
	}{
		{
			name:        "create simple entry",
			entryPath:   "/simpleentry",
			expectError: false,
		},
		{
			name:        "create nested entry",
			entryPath:   "/group1/group2/nestedentry",
			expectError: false,
		},
		{
			name:        "create entry with environment prefix",
			entryPath:   "/testenv/entrywithprefix",
			expectError: false,
		},
		{
			name:        "create entry without leading slash",
			entryPath:   "entrynoslash",
			expectError: false,
		},
		{
			name:        "create duplicate entry",
			entryPath:   "/simpleentry",
			expectError: false, // Should succeed, KeePass allows duplicates?
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := kpMgr.CreateEntry(dbPath, keyfilePath, password, profileName, envName, tt.entryPath)
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verify entry was created
			if !tt.expectError {
				exists, err := kpMgr.EntryExists(dbPath, keyfilePath, password, profileName, envName, tt.entryPath)
				if err != nil {
					t.Errorf("Failed to check entry existence: %v", err)
				}
				if !exists {
					t.Errorf("Entry was not created: %s", tt.entryPath)
				}
			}
		})
	}
}

func TestEntryExists(t *testing.T) {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "keepass_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Setup test files
	dbPath := filepath.Join(tempDir, "test.kdbx")
	keyfilePath := filepath.Join(tempDir, "test.key")
	password := "testpassword"

	// Create KeePass manager
	kpMgr := keepass.NewManager()

	// Generate keyfile first
	err = kpMgr.GenerateKeyfile(keyfilePath)
	if err != nil {
		t.Fatalf("Failed to generate keyfile: %v", err)
	}

	// Create database with profile and environment structure
	err = kpMgr.CreateDatabase(dbPath, keyfilePath, password, "TestDB")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	profileName := "testprofile"
	err = kpMgr.CreateProfile(dbPath, keyfilePath, password, profileName)
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	envName := "testenv"
	err = kpMgr.CreateGroup(dbPath, keyfilePath, password, profileName, "HEAD", envName)
	if err != nil {
		t.Fatalf("Failed to create environment group: %v", err)
	}

	// Create a test entry
	entryPath := "/testentry"
	err = kpMgr.CreateEntry(dbPath, keyfilePath, password, profileName, envName, entryPath)
	if err != nil {
		t.Fatalf("Failed to create test entry: %v", err)
	}

	tests := []struct {
		name      string
		entryPath string
		expected  bool
	}{
		{
			name:      "existing entry",
			entryPath: "/testentry",
			expected:  true,
		},
		{
			name:      "non-existing entry",
			entryPath: "/nonexistent",
			expected:  false,
		},
		{
			name:      "entry with environment prefix",
			entryPath: "/testenv/testentry",
			expected:  true,
		},
		{
			name:      "nested non-existing entry",
			entryPath: "/group/nonexistent",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exists, err := kpMgr.EntryExists(dbPath, keyfilePath, password, profileName, envName, tt.entryPath)
			if err != nil {
				t.Errorf("EntryExists failed: %v", err)
			}
			if exists != tt.expected {
				t.Errorf("EntryExists(%s) = %v, expected %v", tt.entryPath, exists, tt.expected)
			}
		})
	}
}

func TestGetEntriesByEnvironment(t *testing.T) {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "keepass_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Setup test files
	dbPath := filepath.Join(tempDir, "test.kdbx")
	keyfilePath := filepath.Join(tempDir, "test.key")
	password := "testpassword"

	// Create KeePass manager
	kpMgr := keepass.NewManager()

	// Generate keyfile first
	err = kpMgr.GenerateKeyfile(keyfilePath)
	if err != nil {
		t.Fatalf("Failed to generate keyfile: %v", err)
	}

	// Create database with profile and environment structure
	err = kpMgr.CreateDatabase(dbPath, keyfilePath, password, "TestDB")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	profileName := "testprofile"
	err = kpMgr.CreateProfile(dbPath, keyfilePath, password, profileName)
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	envName := "testenv"
	err = kpMgr.CreateGroup(dbPath, keyfilePath, password, profileName, "HEAD", envName)
	if err != nil {
		t.Fatalf("Failed to create environment group: %v", err)
	}

	// Create test entries
	entries := []string{
		"/entry1",
		"/group1/entry2",
		"/group1/group2/entry3",
		"/entry4",
	}

	for _, entry := range entries {
		err := kpMgr.CreateEntry(dbPath, keyfilePath, password, profileName, envName, entry)
		if err != nil {
			t.Fatalf("Failed to create entry %s: %v", entry, err)
		}
	}

	// Test GetEntriesByEnvironment
	result, err := kpMgr.GetEntriesByEnvironment(dbPath, keyfilePath, password, profileName, envName)
	if err != nil {
		t.Fatalf("GetEntriesByEnvironment failed: %v", err)
	}

	// Convert to map for easy checking
	resultMap := make(map[string]bool)
	for _, entry := range result {
		resultMap[entry] = true
	}

	// Check that all expected entries are present
	expectedEntries := []string{
		"entry1",
		"group1/entry2",
		"group1/group2/entry3",
		"entry4",
	}

	for _, expected := range expectedEntries {
		if !resultMap[expected] {
			t.Errorf("Expected entry %s not found in result", expected)
		}
	}

	// Check that we don't have unexpected entries
	if len(result) != len(expectedEntries) {
		t.Errorf("Expected %d entries, got %d", len(expectedEntries), len(result))
	}
}
