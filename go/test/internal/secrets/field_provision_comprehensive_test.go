package secrets_test

import (
	"testing"

	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/tobischo/gokeepasslib/v3"
)

// TestPopulateEntryFields_NewFieldsWithCount tests field population and return count
func TestPopulateEntryFields_NewFieldsWithCount(t *testing.T) {
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
	mockLogger := logger.NewLogger(false) // Non-verbose for testing

	// Create SecretsManager
	manager := secrets.NewSecretsManager(mockDB, mockLogger)

	// Test PopulateEntryFields - should return count of added fields
	fieldsAdded, err := manager.PopulateEntryFields(&entry, "DATABASE_URL", items)
	if err != nil {
		t.Fatalf("PopulateEntryFields failed: %v", err)
	}

	// Verify correct count of fields added
	expectedCount := 2 // Password and URL
	if fieldsAdded != expectedCount {
		t.Errorf("Expected %d fields added, got %d", expectedCount, fieldsAdded)
	}

	// Verify fields were added with correct content
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

// TestPopulateEntryFields_PreventsDuplicatesWithCount tests duplicate prevention and count
func TestPopulateEntryFields_PreventsDuplicatesWithCount(t *testing.T) {
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

	// Test PopulateEntryFields - should only add 1 field (URL)
	fieldsAdded, err := manager.PopulateEntryFields(&entry, "DATABASE_URL", items)
	if err != nil {
		t.Fatalf("PopulateEntryFields failed: %v", err)
	}

	// Verify only 1 field was added (URL, not Password)
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

// TestPopulateEntryFields_AttachmentFieldsIgnored tests that attachment fields are ignored
func TestPopulateEntryFields_AttachmentFieldsIgnored(t *testing.T) {
	// Create test entry
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: "API_TOKEN"},
	})

	// Create test items including attachment fields
	items := []secrets.SecretItem{
		{
			Name:  "API_TOKEN",
			Type:  "envvar",
			Entry: "API_TOKEN",
			Key:   "Password",
		},
		{
			Name:  "SSH_KEY",
			Type:  "envvar",
			Entry: "API_TOKEN",
			Key:   "attachments/id_rsa", // Should be ignored
		},
		{
			Name:  "CERT",
			Type:  "envvar",
			Entry: "API_TOKEN",
			Key:   "attachments/certificate.pem", // Should be ignored
		},
		{
			Name:  "API_URL",
			Type:  "envvar",
			Entry: "API_TOKEN",
			Key:   "URL", // Should be added
		},
	}

	// Create mock database manager and logger
	mockDB := &MockDatabaseManagerForEntries{}
	mockLogger := logger.NewLogger(false)

	// Create SecretsManager
	manager := secrets.NewSecretsManager(mockDB, mockLogger)

	// Test PopulateEntryFields - should only add Password and URL (ignore attachments)
	fieldsAdded, err := manager.PopulateEntryFields(&entry, "API_TOKEN", items)
	if err != nil {
		t.Fatalf("PopulateEntryFields failed: %v", err)
	}

	// Verify only 2 fields were added (Password and URL, not attachments)
	expectedCount := 2
	if fieldsAdded != expectedCount {
		t.Errorf("Expected %d fields added, got %d", expectedCount, fieldsAdded)
	}

	// Verify attachment fields were not added
	for _, value := range entry.Values {
		if value.Key == "attachments/id_rsa" || value.Key == "attachments/certificate.pem" {
			t.Errorf("Attachment field '%s' should not have been added", value.Key)
		}
	}

	// Verify correct fields were added
	expectedFields := map[string]bool{
		"Title":    true,
		"Password": true,
		"URL":      true,
	}

	if len(entry.Values) != len(expectedFields) {
		t.Errorf("Expected %d fields, got %d", len(expectedFields), len(entry.Values))
	}

	for _, value := range entry.Values {
		if !expectedFields[value.Key] {
			t.Errorf("Unexpected field '%s' found", value.Key)
		}
	}
}

// TestPopulateEntryFields_NoMatchingItems tests behavior when no items match the entry
func TestPopulateEntryFields_NoMatchingItems(t *testing.T) {
	// Create test entry
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: "DATABASE_URL"},
	})

	// Create test items that don't reference this entry
	items := []secrets.SecretItem{
		{
			Name:  "API_TOKEN",
			Type:  "envvar",
			Entry: "DIFFERENT_ENTRY", // Different entry
			Key:   "Password",
		},
	}

	// Create mock database manager and logger
	mockDB := &MockDatabaseManagerForEntries{}
	mockLogger := logger.NewLogger(false)

	// Create SecretsManager
	manager := secrets.NewSecretsManager(mockDB, mockLogger)

	// Test PopulateEntryFields - should add 0 fields
	fieldsAdded, err := manager.PopulateEntryFields(&entry, "DATABASE_URL", items)
	if err != nil {
		t.Fatalf("PopulateEntryFields failed: %v", err)
	}

	// Verify no fields were added
	expectedCount := 0
	if fieldsAdded != expectedCount {
		t.Errorf("Expected %d fields added, got %d", expectedCount, fieldsAdded)
	}

	// Verify only original field remains
	if len(entry.Values) != 1 {
		t.Errorf("Expected 1 field (Title), got %d", len(entry.Values))
	}

	if entry.Values[0].Key != "Title" {
		t.Errorf("Expected Title field, got '%s'", entry.Values[0].Key)
	}
}

// TestPopulateEntryFields_PathBasedEntryMatching tests path-based entry matching
func TestPopulateEntryFields_PathBasedEntryMatching(t *testing.T) {
	// Create test entry
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: "API_TOKEN"},
	})

	// Create test items with path-based entry references
	items := []secrets.SecretItem{
		{
			Name:  "API_TOKEN",
			Type:  "envvar",
			Entry: "/tokens/API_TOKEN", // Path-based reference
			Key:   "Password",
		},
		{
			Name:  "API_URL",
			Type:  "envvar",
			Entry: "/tokens/API_TOKEN", // Same path-based reference
			Key:   "URL",
		},
	}

	// Create mock database manager and logger
	mockDB := &MockDatabaseManagerForEntries{}
	mockLogger := logger.NewLogger(false)

	// Create SecretsManager
	manager := secrets.NewSecretsManager(mockDB, mockLogger)

	// Test PopulateEntryFields - should match and add fields
	fieldsAdded, err := manager.PopulateEntryFields(&entry, "API_TOKEN", items)
	if err != nil {
		t.Fatalf("PopulateEntryFields failed: %v", err)
	}

	// Verify correct count of fields added
	expectedCount := 2 // Password and URL
	if fieldsAdded != expectedCount {
		t.Errorf("Expected %d fields added, got %d", expectedCount, fieldsAdded)
	}

	// Verify fields were added
	expectedFields := map[string]bool{
		"Title":    true,
		"Password": true,
		"URL":      true,
	}

	if len(entry.Values) != len(expectedFields) {
		t.Errorf("Expected %d fields, got %d", len(expectedFields), len(entry.Values))
	}

	for _, value := range entry.Values {
		if !expectedFields[value.Key] {
			t.Errorf("Unexpected field '%s' found", value.Key)
		}
	}
}

// TestPopulateEntryFields_EmptyItems tests behavior with empty items slice
func TestPopulateEntryFields_EmptyItems(t *testing.T) {
	// Create test entry
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: "DATABASE_URL"},
	})

	// Empty items slice
	items := []secrets.SecretItem{}

	// Create mock database manager and logger
	mockDB := &MockDatabaseManagerForEntries{}
	mockLogger := logger.NewLogger(false)

	// Create SecretsManager
	manager := secrets.NewSecretsManager(mockDB, mockLogger)

	// Test PopulateEntryFields - should add 0 fields
	fieldsAdded, err := manager.PopulateEntryFields(&entry, "DATABASE_URL", items)
	if err != nil {
		t.Fatalf("PopulateEntryFields failed: %v", err)
	}

	// Verify no fields were added
	expectedCount := 0
	if fieldsAdded != expectedCount {
		t.Errorf("Expected %d fields added, got %d", expectedCount, fieldsAdded)
	}

	// Verify only original field remains
	if len(entry.Values) != 1 {
		t.Errorf("Expected 1 field (Title), got %d", len(entry.Values))
	}
}

// TestPopulateEntryFields_VerboseLogging tests verbose logging behavior
func TestPopulateEntryFields_VerboseLogging(t *testing.T) {
	// Create test entry
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: "DATABASE_URL"},
	})

	// Create test items
	items := []secrets.SecretItem{
		{
			Name:  "DATABASE_URL",
			Type:  "envvar",
			Entry: "DATABASE_URL",
			Key:   "Password",
		},
	}

	// Create mock database manager and verbose logger
	mockDB := &MockDatabaseManagerForEntries{}
	mockLogger := logger.NewLogger(true) // Verbose logging enabled

	// Create SecretsManager
	manager := secrets.NewSecretsManager(mockDB, mockLogger)

	// Test PopulateEntryFields with verbose logging
	fieldsAdded, err := manager.PopulateEntryFields(&entry, "DATABASE_URL", items)
	if err != nil {
		t.Fatalf("PopulateEntryFields failed: %v", err)
	}

	// Verify field was added
	expectedCount := 1
	if fieldsAdded != expectedCount {
		t.Errorf("Expected %d fields added, got %d", expectedCount, fieldsAdded)
	}

	// Note: We can't easily test the actual log output in this test,
	// but we can verify the function completes successfully with verbose logging
}

// TestPopulateEntryFields_MultipleEntriesWithSameName tests handling multiple entries with same name
func TestPopulateEntryFields_MultipleEntriesWithSameName(t *testing.T) {
	// Create test entry
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: "CONFIG"},
	})

	// Create test items with different types but same entry name
	items := []secrets.SecretItem{
		{
			Name:  "DATABASE_URL",
			Type:  "envvar",
			Entry: "CONFIG",
			Key:   "DB_URL",
		},
		{
			Name:  "API_KEY",
			Type:  "envvar",
			Entry: "CONFIG",
			Key:   "API_KEY",
		},
		{
			Name:  "SECRET_TOKEN",
			Type:  "envvar",
			Entry: "CONFIG",
			Key:   "TOKEN",
		},
	}

	// Create mock database manager and logger
	mockDB := &MockDatabaseManagerForEntries{}
	mockLogger := logger.NewLogger(false)

	// Create SecretsManager
	manager := secrets.NewSecretsManager(mockDB, mockLogger)

	// Test PopulateEntryFields - should add all matching fields
	fieldsAdded, err := manager.PopulateEntryFields(&entry, "CONFIG", items)
	if err != nil {
		t.Fatalf("PopulateEntryFields failed: %v", err)
	}

	// Verify correct count of fields added
	expectedCount := 3 // DB_URL, API_KEY, TOKEN
	if fieldsAdded != expectedCount {
		t.Errorf("Expected %d fields added, got %d", expectedCount, fieldsAdded)
	}

	// Verify all fields were added
	expectedFields := map[string]bool{
		"Title":   true,
		"DB_URL":  true,
		"API_KEY": true,
		"TOKEN":   true,
	}

	if len(entry.Values) != len(expectedFields) {
		t.Errorf("Expected %d fields, got %d", len(expectedFields), len(entry.Values))
	}

	for _, value := range entry.Values {
		if !expectedFields[value.Key] {
			t.Errorf("Unexpected field '%s' found", value.Key)
		}
	}
}
