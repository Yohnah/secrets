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

	// Open database session
	err = kpMgr.Open(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer kpMgr.SaveAndClose()

	profileName := "testprofile"
	err = kpMgr.CreateProfile(profileName)
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	envName := "testenv"
	err = kpMgr.CreateGroup(profileName, "HEAD", envName)
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
			err := kpMgr.CreateEntry(profileName, envName, tt.entryPath)
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verify entry was created
			if !tt.expectError {
				exists, err := kpMgr.EntryExists(profileName, envName, tt.entryPath)
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

	// Open database session
	err = kpMgr.Open(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer kpMgr.SaveAndClose()

	profileName := "testprofile"
	err = kpMgr.CreateProfile(profileName)
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	envName := "testenv"
	err = kpMgr.CreateGroup(profileName, "HEAD", envName)
	if err != nil {
		t.Fatalf("Failed to create environment group: %v", err)
	}

	// Create a test entry
	entryPath := "/testentry"
	err = kpMgr.CreateEntry(profileName, envName, entryPath)
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
			exists, err := kpMgr.EntryExists(profileName, envName, tt.entryPath)
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

	// Open database session
	err = kpMgr.Open(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer kpMgr.SaveAndClose()

	profileName := "testprofile"
	err = kpMgr.CreateProfile(profileName)
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	envName := "testenv"
	err = kpMgr.CreateGroup(profileName, "HEAD", envName)
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
		err := kpMgr.CreateEntry(profileName, envName, entry)
		if err != nil {
			t.Fatalf("Failed to create entry %s: %v", entry, err)
		}
	}

	// Test GetEntriesByEnvironment
	result, err := kpMgr.GetEntriesByEnvironment(profileName, envName)
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

func TestPathTraversalPrevention(t *testing.T) {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "keepass_path_test_*")
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

	// Create database
	err = kpMgr.CreateDatabase(dbPath, keyfilePath, password, "TestDB")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	// Test path traversal attempts - these should all fail
	traversalPaths := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32",
		"test/../../../root",
		"valid/../invalid",
	}

	for _, badPath := range traversalPaths {
		t.Run("Traversal_"+badPath, func(t *testing.T) {
			// Try to create database with traversal path
			err := kpMgr.CreateDatabase(badPath, keyfilePath, password, "TestDB")
			if err == nil {
				t.Errorf("Expected error for path traversal attempt: %s", badPath)
			}
		})
	}
}

func TestParameterValidation(t *testing.T) {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "keepass_validation_test_*")
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

	// Test empty parameters for GenerateKeyfile
	t.Run("GenerateKeyfile_EmptyPath", func(t *testing.T) {
		err := kpMgr.GenerateKeyfile("")
		if err == nil {
			t.Error("Expected error for empty keyfile path")
		}
	})

	// Test empty parameters for CreateDatabase
	t.Run("CreateDatabase_EmptyDbPath", func(t *testing.T) {
		err := kpMgr.CreateDatabase("", keyfilePath, password, "TestDB")
		if err == nil {
			t.Error("Expected error for empty database path")
		}
	})

	t.Run("CreateDatabase_EmptyKeyfilePath", func(t *testing.T) {
		err := kpMgr.CreateDatabase(dbPath, "", password, "TestDB")
		if err == nil {
			t.Error("Expected error for empty keyfile path")
		}
	})

	t.Run("CreateDatabase_EmptyPassword", func(t *testing.T) {
		err := kpMgr.CreateDatabase(dbPath, keyfilePath, "", "TestDB")
		if err == nil {
			t.Error("Expected error for empty password")
		}
	})

	t.Run("CreateDatabase_EmptyRootGroup", func(t *testing.T) {
		err := kpMgr.CreateDatabase(dbPath, keyfilePath, password, "")
		if err == nil {
			t.Error("Expected error for empty root group name")
		}
	})
}
