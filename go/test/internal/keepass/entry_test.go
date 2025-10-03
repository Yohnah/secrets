package keepass_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/keepass"
)

func TestKeePassManager_CreateEntry_Success(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "keepass_entry_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.kdbx")
	keyfilePath := filepath.Join(tempDir, "test.keyfile")
	password := "test_password_123"

	dbMgr := keepass.NewDatabaseManager()

	// Create database first
	err = dbMgr.Create(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	// Open database to test entry creation
	db, err := dbMgr.OpenDatabase(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	// Create a test group first
	rootGroup := &db.Content.Root.Groups[0] // "SECRETS YOHNAH" group
	testGroup := dbMgr.CreateGroup(rootGroup, "test_environment")

	// Test entry creation
	entryTitle := "TEST_ENTRY"
	entry := dbMgr.CreateEntry(testGroup, entryTitle)

	if entry == nil {
		t.Fatal("Expected entry to be created, got nil")
	}

	// Verify entry is added to group
	found := false
	for i := range testGroup.Entries {
		if testGroup.Entries[i].GetTitle() == entryTitle {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected entry '%s' to be found in group, but it wasn't", entryTitle)
	}
}

func TestKeePassManager_CreateGroupChain_Success(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "keepass_groupchain_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.kdbx")
	keyfilePath := filepath.Join(tempDir, "test.keyfile")
	password := "test_password_123"

	dbMgr := keepass.NewDatabaseManager()

	// Create database first
	err = dbMgr.Create(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	// Open database to test group chain creation
	db, err := dbMgr.OpenDatabase(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	// Create a test parent group
	rootGroup := &db.Content.Root.Groups[0] // "SECRETS YOHNAH" group
	parentGroup := dbMgr.CreateGroup(rootGroup, "test_environment")

	// Test nested group chain creation
	pathSegments := []string{"path", "to", "nested"}
	finalGroup := dbMgr.CreateGroupChain(parentGroup, pathSegments)

	if finalGroup == nil {
		t.Fatal("Expected final group to be created, got nil")
	}

	// Verify the chain exists
	currentGroup := parentGroup
	for _, segment := range pathSegments {
		found := false
		for i := range currentGroup.Groups {
			if currentGroup.Groups[i].Name == segment {
				currentGroup = &currentGroup.Groups[i]
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected group '%s' to exist in chain, but it wasn't found", segment)
		}
	}

	// Verify final group name matches last segment
	if finalGroup.Name != pathSegments[len(pathSegments)-1] {
		t.Errorf("Expected final group name '%s', got '%s'", pathSegments[len(pathSegments)-1], finalGroup.Name)
	}
}

func TestKeePassManager_CreateGroupChain_ExistingGroups(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "keepass_existing_groups_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.kdbx")
	keyfilePath := filepath.Join(tempDir, "test.keyfile")
	password := "test_password_123"

	dbMgr := keepass.NewDatabaseManager()

	// Create database first
	err = dbMgr.Create(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	// Open database to test group chain creation
	db, err := dbMgr.OpenDatabase(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	// Create a test parent group
	rootGroup := &db.Content.Root.Groups[0] // "SECRETS YOHNAH" group
	parentGroup := dbMgr.CreateGroup(rootGroup, "test_environment")

	// Create some groups manually first
	firstGroup := dbMgr.CreateGroup(parentGroup, "existing")
	dbMgr.CreateGroup(firstGroup, "path")

	// Test creating chain where some groups already exist
	pathSegments := []string{"existing", "path", "new"}
	finalGroup := dbMgr.CreateGroupChain(parentGroup, pathSegments)

	if finalGroup == nil {
		t.Fatal("Expected final group to be created, got nil")
	}

	// Verify the final group name
	if finalGroup.Name != "new" {
		t.Errorf("Expected final group name 'new', got '%s'", finalGroup.Name)
	}

	// Verify no duplicate groups were created
	existingGroupCount := 0
	for i := range parentGroup.Groups {
		if parentGroup.Groups[i].Name == "existing" {
			existingGroupCount++
		}
	}

	if existingGroupCount != 1 {
		t.Errorf("Expected exactly 1 'existing' group, found %d", existingGroupCount)
	}
}

func TestKeePassManager_FindEntriesByTitle_Success(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "keepass_find_entries_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.kdbx")
	keyfilePath := filepath.Join(tempDir, "test.keyfile")
	password := "test_password_123"

	dbMgr := keepass.NewDatabaseManager()

	// Create database first
	err = dbMgr.Create(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	// Open database to test entry finding
	db, err := dbMgr.OpenDatabase(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	// Create a test group and entries
	rootGroup := &db.Content.Root.Groups[0] // "SECRETS YOHNAH" group
	testGroup := dbMgr.CreateGroup(rootGroup, "test_environment")

	// Create multiple entries
	entry1 := dbMgr.CreateEntry(testGroup, "ENTRY_1")
	entry2 := dbMgr.CreateEntry(testGroup, "ENTRY_2")
	entry3 := dbMgr.CreateEntry(testGroup, "ENTRY_1") // Duplicate title

	// Test finding entries by title
	foundEntries := dbMgr.FindEntriesByTitle(testGroup, "ENTRY_1")

	// Should find 2 entries with title "ENTRY_1"
	if len(foundEntries) != 2 {
		t.Errorf("Expected 2 entries with title 'ENTRY_1', found %d", len(foundEntries))
	}

	// Test finding non-existent entry
	notFoundEntries := dbMgr.FindEntriesByTitle(testGroup, "NON_EXISTENT")
	if len(notFoundEntries) != 0 {
		t.Errorf("Expected 0 entries with title 'NON_EXISTENT', found %d", len(notFoundEntries))
	}

	// Verify entries are the correct ones
	for _, entry := range foundEntries {
		if entry.GetTitle() != "ENTRY_1" {
			t.Errorf("Expected entry title 'ENTRY_1', got '%s'", entry.GetTitle())
		}
	}

	// Suppress unused variable warnings
	_ = entry1
	_ = entry2
	_ = entry3
}

func TestKeePassManager_SetEntryField_Success(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "keepass_set_field_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.kdbx")
	keyfilePath := filepath.Join(tempDir, "test.keyfile")
	password := "test_password_123"

	dbMgr := keepass.NewDatabaseManager()

	// Create database first
	err = dbMgr.Create(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	// Open database to test field setting
	db, err := dbMgr.OpenDatabase(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	// Create a test group and entry
	rootGroup := &db.Content.Root.Groups[0] // "SECRETS YOHNAH" group
	testGroup := dbMgr.CreateGroup(rootGroup, "test_environment")
	entry := dbMgr.CreateEntry(testGroup, "TEST_ENTRY")

	// Test setting entry fields
	dbMgr.SetEntryField(entry, "Password", "secret_password_123")
	dbMgr.SetEntryField(entry, "UserName", "test_user")
	dbMgr.SetEntryField(entry, "URL", "https://example.com")
	dbMgr.SetEntryField(entry, "CustomField", "custom_value")

	// Verify fields were set correctly
	passwordValue := entry.GetPassword()
	if passwordValue != "secret_password_123" {
		t.Errorf("Expected password 'secret_password_123', got '%s'", passwordValue)
	}

	usernameValue := entry.GetContent("UserName")
	if usernameValue != "test_user" {
		t.Errorf("Expected username 'test_user', got '%s'", usernameValue)
	}

	urlValue := entry.GetContent("URL")
	if urlValue != "https://example.com" {
		t.Errorf("Expected URL 'https://example.com', got '%s'", urlValue)
	}

	// Check custom field
	customValue := entry.GetContent("CustomField")
	if customValue != "custom_value" {
		t.Errorf("Expected custom field 'custom_value', got '%s'", customValue)
	}
}
