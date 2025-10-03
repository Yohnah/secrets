package keepass_test

import (
	"testing"

	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/tobischo/gokeepasslib/v3"
)

func TestKeePassManager_AddAttachment(t *testing.T) {
	manager := keepass.NewDatabaseManager()

	// Create a test database and entry
	db := gokeepasslib.NewDatabase()
	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Test Root"
	db.Content.Root.Groups = []gokeepasslib.Group{rootGroup}

	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: "Test Entry"},
	})

	testContent := []byte("Test attachment content")

	// Test successful attachment addition
	err := manager.AddAttachment(db, &entry, "test-file.txt", testContent)
	if err != nil {
		t.Fatalf("AddAttachment failed: %v", err)
	}

	// Verify attachment was added
	if len(entry.Binaries) != 1 {
		t.Fatalf("Expected 1 attachment, got %d", len(entry.Binaries))
	}

	if entry.Binaries[0].Name != "test-file.txt" {
		t.Errorf("Expected attachment name 'test-file.txt', got '%s'", entry.Binaries[0].Name)
	}

	// Test duplicate attachment prevention
	err = manager.AddAttachment(db, &entry, "test-file.txt", testContent)
	if err == nil {
		t.Error("Expected error when adding duplicate attachment, got nil")
	}

	// Test nil database validation
	err = manager.AddAttachment(nil, &entry, "test2.txt", testContent)
	if err == nil {
		t.Error("Expected error with nil database, got nil")
	}

	// Test nil entry validation
	err = manager.AddAttachment(db, nil, "test3.txt", testContent)
	if err == nil {
		t.Error("Expected error with nil entry, got nil")
	}

	// Test empty filename validation
	err = manager.AddAttachment(db, &entry, "", testContent)
	if err == nil {
		t.Error("Expected error with empty filename, got nil")
	}
}

func TestKeePassManager_HasAttachment(t *testing.T) {
	manager := keepass.NewDatabaseManager()

	// Create a test entry with attachment
	entry := gokeepasslib.NewEntry()
	entry.Binaries = []gokeepasslib.BinaryReference{
		{Name: "existing-file.txt"},
	}

	// Test existing attachment
	if !manager.HasAttachment(&entry, "existing-file.txt") {
		t.Error("Expected HasAttachment to return true for existing attachment")
	}

	// Test non-existing attachment
	if manager.HasAttachment(&entry, "non-existing.txt") {
		t.Error("Expected HasAttachment to return false for non-existing attachment")
	}

	// Test nil entry
	if manager.HasAttachment(nil, "test.txt") {
		t.Error("Expected HasAttachment to return false for nil entry")
	}

	// Test empty filename
	if manager.HasAttachment(&entry, "") {
		t.Error("Expected HasAttachment to return false for empty filename")
	}
}

func TestKeePassManager_ListAttachments(t *testing.T) {
	manager := keepass.NewDatabaseManager()

	// Test empty entry
	entry := gokeepasslib.NewEntry()
	attachments := manager.ListAttachments(&entry)
	if len(attachments) != 0 {
		t.Errorf("Expected 0 attachments for empty entry, got %d", len(attachments))
	}

	// Test entry with multiple attachments
	entry.Binaries = []gokeepasslib.BinaryReference{
		{Name: "file1.txt"},
		{Name: "file2.pdf"},
		{Name: "file3.jpg"},
	}

	attachments = manager.ListAttachments(&entry)
	expectedFiles := []string{"file1.txt", "file2.pdf", "file3.jpg"}

	if len(attachments) != len(expectedFiles) {
		t.Fatalf("Expected %d attachments, got %d", len(expectedFiles), len(attachments))
	}

	// Verify all filenames are present
	for i, expected := range expectedFiles {
		if attachments[i] != expected {
			t.Errorf("Expected attachment[%d] = '%s', got '%s'", i, expected, attachments[i])
		}
	}

	// Test nil entry
	attachments = manager.ListAttachments(nil)
	if len(attachments) != 0 {
		t.Errorf("Expected 0 attachments for nil entry, got %d", len(attachments))
	}
}

func TestKeePassManager_AttachmentIntegration(t *testing.T) {
	manager := keepass.NewDatabaseManager()

	// Create a test database and entry
	db := gokeepasslib.NewDatabase()
	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Test Root"
	db.Content.Root.Groups = []gokeepasslib.Group{rootGroup}

	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: "Integration Test Entry"},
	})

	// Test complete workflow: add multiple attachments and verify
	files := map[string][]byte{
		"document.pdf": []byte("PDF content"),
		"image.jpg":    []byte("JPEG content"),
		"config.json":  []byte(`{"test": true}`),
	}

	// Add all attachments
	for filename, content := range files {
		err := manager.AddAttachment(db, &entry, filename, content)
		if err != nil {
			t.Fatalf("Failed to add attachment '%s': %v", filename, err)
		}
	}

	// Verify all attachments exist
	for filename := range files {
		if !manager.HasAttachment(&entry, filename) {
			t.Errorf("Attachment '%s' not found after adding", filename)
		}
	}

	// Verify list contains all files
	attachments := manager.ListAttachments(&entry)
	if len(attachments) != len(files) {
		t.Fatalf("Expected %d attachments in list, got %d", len(files), len(attachments))
	}

	// Verify each expected file is in the list
	for filename := range files {
		found := false
		for _, listed := range attachments {
			if listed == filename {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("File '%s' not found in attachment list", filename)
		}
	}
}
