package keepass_test

import (
	"testing"

	"github.com/Yohnah/secrets/tests/testhelpers"
)

func TestCreateEntry(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestGetFieldValue(t *testing.T) {
	t.Parallel()
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

	// Set standard field values
	err = testDB.Manager.SetStandardField(profileName, envName, entryPath, "UserName", "testuser")
	if err != nil {
		t.Fatalf("Failed to set UserName: %v", err)
	}

	err = testDB.Manager.SetStandardField(profileName, envName, entryPath, "Password", "testpass123")
	if err != nil {
		t.Fatalf("Failed to set Password: %v", err)
	}

	err = testDB.Manager.SetStandardField(profileName, envName, entryPath, "URL", "https://example.com")
	if err != nil {
		t.Fatalf("Failed to set URL: %v", err)
	}

	// Set a custom field
	err = testDB.Manager.SetCustomField(profileName, envName, entryPath, "CustomField", "custom_value")
	if err != nil {
		t.Fatalf("Failed to set custom field: %v", err)
	}

	// Set an empty field
	err = testDB.Manager.SetStandardField(profileName, envName, entryPath, "Notes", "")
	if err != nil {
		t.Fatalf("Failed to set empty Notes: %v", err)
	}

	tests := []struct {
		name          string
		fieldName     string
		expectedValue string
		expectError   bool
	}{
		{
			name:          "get standard field - case insensitive",
			fieldName:     "username",
			expectedValue: "testuser",
			expectError:   false,
		},
		{
			name:          "get standard field - exact case",
			fieldName:     "UserName",
			expectedValue: "testuser",
			expectError:   false,
		},
		{
			name:          "get password field",
			fieldName:     "password",
			expectedValue: "testpass123",
			expectError:   false,
		},
		{
			name:          "get URL field",
			fieldName:     "url",
			expectedValue: "https://example.com",
			expectError:   false,
		},
		{
			name:          "get custom field - case sensitive",
			fieldName:     "CustomField",
			expectedValue: "custom_value",
			expectError:   false,
		},
		{
			name:          "get empty field",
			fieldName:     "Notes",
			expectedValue: "",
			expectError:   false,
		},
		{
			name:          "get non-existent field",
			fieldName:     "NonExistentField",
			expectedValue: "",
			expectError:   true,
		},
		{
			name:          "attachment field",
			fieldName:     "attachments/test.txt",
			expectedValue: "",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := testDB.Manager.GetFieldValue(profileName, envName, entryPath, tt.fieldName)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
				if value != tt.expectedValue {
					t.Errorf("GetFieldValue() = %q, expected %q", value, tt.expectedValue)
				}
			}
		})
	}
}

func TestGetFieldValue_EntryNotFound(t *testing.T) {
	t.Parallel()
	// Setup test database with session
	testDB, cleanup := testhelpers.SetupTestDatabaseWithSession(t, "TestDB")
	defer cleanup()

	// Create profile and environment
	profileName := "testprofile"
	envName := "testenv"
	testhelpers.CreateTestProfile(t, testDB.Manager, profileName, envName)

	// Try to get field value from non-existent entry
	_, err := testDB.Manager.GetFieldValue(profileName, envName, "/nonexistent", "UserName")
	if err == nil {
		t.Error("Expected error for non-existent entry")
	}
}

func TestGetAttachmentContent(t *testing.T) {
	t.Parallel()
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

	// Create attachments with different content
	defaultContent := []byte("Attachment pending to be filled by the developer")
	err = testDB.Manager.CreateAttachment(profileName, envName, entryPath, "default.txt", defaultContent)
	if err != nil {
		t.Fatalf("Failed to create default attachment: %v", err)
	}

	realContent := []byte("This is real attachment content")
	err = testDB.Manager.CreateAttachment(profileName, envName, entryPath, "data.txt", realContent)
	if err != nil {
		t.Fatalf("Failed to create data attachment: %v", err)
	}

	emptyContent := []byte{}
	err = testDB.Manager.CreateAttachment(profileName, envName, entryPath, "empty.txt", emptyContent)
	if err != nil {
		t.Fatalf("Failed to create empty attachment: %v", err)
	}

	tests := []struct {
		name           string
		attachmentName string
		expectedLength int
		expectedString string
		expectError    bool
	}{
		{
			name:           "get default placeholder attachment",
			attachmentName: "default.txt",
			expectedLength: len(defaultContent),
			expectedString: "Attachment pending to be filled by the developer",
			expectError:    false,
		},
		{
			name:           "get attachment with data",
			attachmentName: "data.txt",
			expectedLength: len(realContent),
			expectedString: "This is real attachment content",
			expectError:    false,
		},
		{
			name:           "get empty attachment",
			attachmentName: "empty.txt",
			expectedLength: 0,
			expectedString: "",
			expectError:    false,
		},
		{
			name:           "get non-existent attachment",
			attachmentName: "notfound.txt",
			expectedLength: 0,
			expectedString: "",
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, err := testDB.Manager.GetAttachmentContent(profileName, envName, entryPath, tt.attachmentName)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
				if len(content) != tt.expectedLength {
					t.Errorf("GetAttachmentContent() length = %d, expected %d", len(content), tt.expectedLength)
				}
				if string(content) != tt.expectedString {
					t.Errorf("GetAttachmentContent() = %q, expected %q", string(content), tt.expectedString)
				}
			}
		})
	}
}

func TestGetAttachmentContent_EntryNotFound(t *testing.T) {
	t.Parallel()
	// Setup test database with session
	testDB, cleanup := testhelpers.SetupTestDatabaseWithSession(t, "TestDB")
	defer cleanup()

	// Create profile and environment
	profileName := "testprofile"
	envName := "testenv"
	testhelpers.CreateTestProfile(t, testDB.Manager, profileName, envName)

	// Try to get attachment from non-existent entry
	_, err := testDB.Manager.GetAttachmentContent(profileName, envName, "/nonexistent", "file.txt")
	if err == nil {
		t.Error("Expected error for non-existent entry")
	}
}

func TestAttachmentsAfterFieldModifications(t *testing.T) {
	t.Parallel()
	// Regression test for: attachment IDs becoming invalid after modifying other fields
	// This test ensures that attachments remain accessible after database modifications

	testDB, cleanup := testhelpers.SetupTestDatabaseWithSession(t, "TestDB")
	defer cleanup()

	// Create profile and environment
	profileName := "testprofile"
	envName := "testenv"
	testhelpers.CreateTestProfile(t, testDB.Manager, profileName, envName)

	// Create two entries: one with regular field, one with attachment
	entry1 := "/entry1"
	entry2 := "/entry2"
	err := testDB.Manager.CreateEntry(profileName, envName, entry1)
	if err != nil {
		t.Fatalf("Failed to create entry1: %v", err)
	}
	err = testDB.Manager.CreateEntry(profileName, envName, entry2)
	if err != nil {
		t.Fatalf("Failed to create entry2: %v", err)
	}

	// Create attachment in entry2
	attachmentContent := []byte("Attachment pending to be filled by the developer")
	err = testDB.Manager.CreateAttachment(profileName, envName, entry2, "test.txt", attachmentContent)
	if err != nil {
		t.Fatalf("Failed to create attachment: %v", err)
	}

	// Verify attachment exists and has correct content
	content, err := testDB.Manager.GetAttachmentContent(profileName, envName, entry2, "test.txt")
	if err != nil {
		t.Errorf("Failed to get attachment before modification: %v", err)
	}
	if string(content) != string(attachmentContent) {
		t.Errorf("Attachment content mismatch before modification: got %q, want %q", string(content), string(attachmentContent))
	}

	// Now modify a field in entry1 (simulating user adding data)
	err = testDB.Manager.SetStandardField(profileName, envName, entry1, "Password", "new_password_123")
	if err != nil {
		t.Fatalf("Failed to set field: %v", err)
	}

	// Save and reload database (simulating what happens in real usage)
	err = testDB.Manager.SaveAndClose()
	if err != nil {
		t.Fatalf("Failed to save database: %v", err)
	}
	err = testDB.Manager.Open(testDB.DBPath, testDB.KeyfilePath, testDB.Password)
	if err != nil {
		t.Fatalf("Failed to reopen database: %v", err)
	}

	// Verify attachment is still accessible with correct content
	content, err = testDB.Manager.GetAttachmentContent(profileName, envName, entry2, "test.txt")
	if err != nil {
		t.Errorf("Failed to get attachment after modification: %v", err)
	}
	if string(content) != string(attachmentContent) {
		t.Errorf("Attachment content mismatch after modification: got %q, want %q", string(content), string(attachmentContent))
	}
}

