package secrets_test

import (
	"testing"

	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/tobischo/gokeepasslib/v3"
)

func TestSecretsManager_PopulateEntryAttachments_Basic(t *testing.T) {
	log := logger.NewLogger(false)
	mockDB := &MockDatabaseManager{}
	manager := secrets.NewSecretsManager(mockDB, log, nil, nil)

	// Create test database and entry
	db := gokeepasslib.NewDatabase()
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: "TestEntry"},
	})

	// Test items with attachments
	items := []secrets.SecretItem{
		{
			Name:  "item1",
			Entry: "TestEntry",
			Key:   "attachments/document.pdf",
			Type:  "text",
		},
	}

	// Test successful attachment population
	count, err := manager.PopulateEntryAttachments(db, &entry, "TestEntry", items)
	if err != nil {
		t.Fatalf("PopulateEntryAttachments failed: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 attachment added, got %d", count)
	}

	// Verify attachment was added
	if len(entry.Binaries) != 1 {
		t.Errorf("Expected 1 binary in entry, got %d", len(entry.Binaries))
	}

	if entry.Binaries[0].Name != "document.pdf" {
		t.Errorf("Expected 'document.pdf' attachment, got '%s'", entry.Binaries[0].Name)
	}
}
