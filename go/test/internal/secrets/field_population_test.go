package secrets_test

import (
	"testing"

	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/tobischo/gokeepasslib/v3"
)

func TestPopulateEntryFields_NewFields(t *testing.T) {
	// Create test entry with basic structure
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: "DATABASE_URL"},
	})

	// Create test items that reference this entry
	items := []secrets.SecretItem{
		{
			Name:  "DATABASE_URL",
			Type:  "envvar",
			Entry: "DATABASE_URL",
			Key:   "Password",
		},
		{
			Name:  "DB_HOST",
			Type:  "envvar",
			Entry: "DATABASE_URL",
			Key:   "URL",
		},
	}

	// Create mock database manager and logger
	mockDB := &MockDatabaseManagerForEntries{}
	mockLogger := logger.NewLogger(false)

	// Create SecretsManager
	manager := secrets.NewSecretsManager(mockDB, mockLogger)

	// Test PopulateEntryFields
	fieldsAdded, err := manager.PopulateEntryFields(&entry, "DATABASE_URL", items)
	if err != nil {
		t.Fatalf("PopulateEntryFields failed: %v", err)
	}

	// Verify correct number of fields were added
	expectedCount := 2
	if fieldsAdded != expectedCount {
		t.Errorf("Expected %d fields added, got %d", expectedCount, fieldsAdded)
	}

	// Verify fields were added
	expectedFields := map[string]string{
		"Title":    "DATABASE_URL",
		"Password": "Content pending to be provided by user",
		"URL":      "Content pending to be provided by user",
	}

	if len(entry.Values) != len(expectedFields) {
		t.Errorf("Expected %d fields, got %d", len(expectedFields), len(entry.Values))
	}

	for _, value := range entry.Values {
		expectedContent, exists := expectedFields[value.Key]
		if !exists {
			t.Errorf("Unexpected field '%s' found", value.Key)
			continue
		}

		if value.Value.Content != expectedContent {
			t.Errorf("Field '%s': expected content '%s', got '%s'", value.Key, expectedContent, value.Value.Content)
		}
	}
}

func TestIsEntryMatchForItem_SimpleEntryName(t *testing.T) {
	// Create test entry
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: "DATABASE_URL"},
	})

	// Create test item with simple entry reference
	item := secrets.SecretItem{
		Name:  "DB_URL",
		Type:  "envvar",
		Entry: "DATABASE_URL", // Simple name, no path
		Key:   "Password",
	}

	// Create mock database manager and logger
	mockDB := &MockDatabaseManagerForEntries{}
	mockLogger := logger.NewLogger(false)

	// Create SecretsManager
	manager := secrets.NewSecretsManager(mockDB, mockLogger)

	// Test entry matching
	matches := manager.IsEntryMatchForItem(&entry, item)
	if !matches {
		t.Error("Entry should match item with simple entry name")
	}
}

func TestPopulateEntryFields_PreventsDuplicates(t *testing.T) {
	// Create test entry with existing Password field
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: "DATABASE_URL"},
	})
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Password",
		Value: gokeepasslib.V{Content: "existing-password"},
	})

	// Create test items that would create duplicate Password field
	items := []secrets.SecretItem{
		{
			Name:  "DATABASE_URL",
			Type:  "envvar",
			Entry: "DATABASE_URL",
			Key:   "Password", // This already exists
		},
		{
			Name:  "DB_URL",
			Type:  "envvar",
			Entry: "DATABASE_URL",
			Key:   "URL", // This is new
		},
	}

	// Create mock database manager and logger
	mockDB := &MockDatabaseManagerForEntries{}
	mockLogger := logger.NewLogger(false)

	// Create SecretsManager
	manager := secrets.NewSecretsManager(mockDB, mockLogger)

	// Test PopulateEntryFields
	fieldsAdded, err := manager.PopulateEntryFields(&entry, "DATABASE_URL", items)
	if err != nil {
		t.Fatalf("PopulateEntryFields failed: %v", err)
	}

	// Verify only 1 field was added (URL, not Password duplicate)
	expectedCount := 1
	if fieldsAdded != expectedCount {
		t.Errorf("Expected %d fields added, got %d", expectedCount, fieldsAdded)
	}

	// Verify no duplicate Password field was created
	passwordCount := 0
	urlCount := 0
	for _, value := range entry.Values {
		if value.Key == "Password" {
			passwordCount++
			// Original value should be preserved
			if value.Value.Content != "existing-password" {
				t.Errorf("Password field content was modified: expected 'existing-password', got '%s'", value.Value.Content)
			}
		}
		if value.Key == "URL" {
			urlCount++
			// New field should have default content
			if value.Value.Content != "Content pending to be provided by user" {
				t.Errorf("URL field content: expected 'Content pending to be provided by user', got '%s'", value.Value.Content)
			}
		}
	}

	if passwordCount != 1 {
		t.Errorf("Expected exactly 1 Password field, got %d", passwordCount)
	}
	if urlCount != 1 {
		t.Errorf("Expected exactly 1 URL field, got %d", urlCount)
	}
}

func TestIsEntryMatchForItem_PathBasedEntryName(t *testing.T) {
	// Create test entry
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: "API_TOKEN"},
	})

	// Create test item with path-based entry reference
	item := secrets.SecretItem{
		Name:  "API_TOKEN",
		Type:  "envvar",
		Entry: "/tokens/API_TOKEN", // Path-based reference
		Key:   "Password",
	}

	// Create mock database manager and logger
	mockDB := &MockDatabaseManagerForEntries{}
	mockLogger := logger.NewLogger(false)

	// Create SecretsManager
	manager := secrets.NewSecretsManager(mockDB, mockLogger)

	// Test entry matching
	matches := manager.IsEntryMatchForItem(&entry, item)
	if !matches {
		t.Error("Entry should match item with path-based entry name")
	}
}
