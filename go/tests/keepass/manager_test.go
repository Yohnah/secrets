package keepass_test

import (
	"testing"

	"github.com/Yohnah/secrets/internal/testhelpers"
)

func TestCreateEntry(t *testing.T) {
	// Setup test database with session
	testDB, cleanup := testhelpers.SetupTestDatabaseWithSession(t, "TestDB")
	defer cleanup()

	// Create profile and environment
	profileName := "testprofile"
	envName := "testenv"
	testhelpers.CreateTestProfile(t, testDB.Manager, profileName, envName)

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
			err := testDB.Manager.CreateEntry(profileName, envName, tt.entryPath)
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Verify entry was created
			if !tt.expectError {
				exists, err := testDB.Manager.EntryExists(profileName, envName, tt.entryPath)
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
	// Setup test database with session
	testDB, cleanup := testhelpers.SetupTestDatabaseWithSession(t, "TestDB")
	defer cleanup()

	// Create profile and environment
	profileName := "testprofile"
	envName := "testenv"
	testhelpers.CreateTestProfile(t, testDB.Manager, profileName, envName)

	// Create a test entry
	entryPath := "/testentry"
	err := testDB.Manager.CreateEntry(profileName, envName, entryPath)
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
			expected:  false, // Changed: no longer removes environment prefix
		},
		{
			name:      "nested non-existing entry",
			entryPath: "/group/nonexistent",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exists, err := testDB.Manager.EntryExists(profileName, envName, tt.entryPath)
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
	// Setup test database with session
	testDB, cleanup := testhelpers.SetupTestDatabaseWithSession(t, "TestDB")
	defer cleanup()

	// Create profile and environment
	profileName := "testprofile"
	envName := "testenv"
	testhelpers.CreateTestProfile(t, testDB.Manager, profileName, envName)

	// Create test entries
	entries := []string{
		"/entry1",
		"/group1/entry2",
		"/group1/group2/entry3",
		"/entry4",
	}

	for _, entry := range entries {
		err := testDB.Manager.CreateEntry(profileName, envName, entry)
		if err != nil {
			t.Fatalf("Failed to create entry %s: %v", entry, err)
		}
	}

	// Test GetEntriesByEnvironment
	result, err := testDB.Manager.GetEntriesByEnvironment(profileName, envName)
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
	// Setup test database
	testDB, cleanup := testhelpers.SetupTestDatabase(t, "TestDB")
	defer cleanup()

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
			err := testDB.Manager.CreateDatabase(badPath, testDB.KeyfilePath, testDB.Password, "TestDB")
			if err == nil {
				t.Errorf("Expected error for path traversal attempt: %s", badPath)
			}
		})
	}
}

func TestParameterValidation(t *testing.T) {
	// Setup test database
	testDB, cleanup := testhelpers.SetupTestDatabase(t, "TestDB")
	defer cleanup()

	// Test empty parameters for GenerateKeyfile
	t.Run("GenerateKeyfile_EmptyPath", func(t *testing.T) {
		err := testDB.Manager.GenerateKeyfile("")
		if err == nil {
			t.Error("Expected error for empty keyfile path")
		}
	})

	// Test empty parameters for CreateDatabase
	t.Run("CreateDatabase_EmptyDbPath", func(t *testing.T) {
		err := testDB.Manager.CreateDatabase("", testDB.KeyfilePath, testDB.Password, "TestDB")
		if err == nil {
			t.Error("Expected error for empty database path")
		}
	})

	t.Run("CreateDatabase_EmptyKeyfilePath", func(t *testing.T) {
		err := testDB.Manager.CreateDatabase(testDB.DBPath, "", testDB.Password, "TestDB")
		if err == nil {
			t.Error("Expected error for empty keyfile path")
		}
	})

	t.Run("CreateDatabase_EmptyPassword", func(t *testing.T) {
		err := testDB.Manager.CreateDatabase(testDB.DBPath, testDB.KeyfilePath, "", "TestDB")
		if err == nil {
			t.Error("Expected error for empty password")
		}
	})

	t.Run("CreateDatabase_EmptyRootGroup", func(t *testing.T) {
		err := testDB.Manager.CreateDatabase(testDB.DBPath, testDB.KeyfilePath, testDB.Password, "")
		if err == nil {
			t.Error("Expected error for empty root group name")
		}
	})
}
