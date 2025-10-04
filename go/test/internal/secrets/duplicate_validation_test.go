package secrets_test

import (
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/tobischo/gokeepasslib/v3"
)

func TestValidateEntryFieldUniqueness_NoDuplicates(t *testing.T) {
	// Test with no duplicate fields - should pass
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Password",
		Value: gokeepasslib.V{Content: "secret123"},
	})
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "UserName",
		Value: gokeepasslib.V{Content: "admin"},
	})
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "URL",
		Value: gokeepasslib.V{Content: "https://example.com"},
	})

	// This should not return an error
	err := secrets.ValidateEntryFieldUniqueness(&entry, "TEST_ENTRY")
	if err != nil {
		t.Errorf("Expected no error for unique fields, got: %v", err)
	}
}

func TestValidateEntryFieldUniqueness_WithDuplicates(t *testing.T) {
	// Test with duplicate fields - should fail
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Password",
		Value: gokeepasslib.V{Content: "secret123"},
	})
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Password", // Duplicate!
		Value: gokeepasslib.V{Content: "another_secret"},
	})
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "UserName",
		Value: gokeepasslib.V{Content: "admin"},
	})

	// This should return an error
	err := secrets.ValidateEntryFieldUniqueness(&entry, "TEST_ENTRY")
	if err == nil {
		t.Error("Expected error for duplicate fields, got nil")
	}

	expectedError := "duplicate field detected: 'Password' found 2 times in entry 'TEST_ENTRY'. Please correct manually in KeePass database"
	if err.Error() != expectedError {
		t.Errorf("Expected error message '%s', got '%s'", expectedError, err.Error())
	}
}

func TestValidateEntryFieldUniqueness_MultipleDuplicates(t *testing.T) {
	// Test with multiple types of duplicates
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Password",
		Value: gokeepasslib.V{Content: "secret1"},
	})
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Password", // Duplicate!
		Value: gokeepasslib.V{Content: "secret2"},
	})
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Password", // Another duplicate!
		Value: gokeepasslib.V{Content: "secret3"},
	})

	// This should return an error
	err := secrets.ValidateEntryFieldUniqueness(&entry, "TEST_ENTRY")
	if err == nil {
		t.Error("Expected error for multiple duplicate fields, got nil")
	}

	expectedError := "duplicate field detected: 'Password' found 3 times in entry 'TEST_ENTRY'. Please correct manually in KeePass database"
	if err.Error() != expectedError {
		t.Errorf("Expected error message '%s', got '%s'", expectedError, err.Error())
	}
}

func TestSecretsManager_DuplicateEnvironmentDetection(t *testing.T) {
	// Create mock with duplicate environments
	mockDB := NewMockDatabaseManagerForEntries()
	mockLogger := logger.NewLogger(false)
	manager := secrets.NewSecretsManager(mockDB, mockLogger, nil, nil)

	// Simulate finding duplicate environments
	mockDB.FindGroupsByNameInParentFunc = func(parentGroup *gokeepasslib.Group, groupName string) ([]*gokeepasslib.Group, error) {
		if groupName == "development" {
			// Return 2 groups to simulate duplicate
			group1 := gokeepasslib.NewGroup()
			group1.Name = "development"
			group2 := gokeepasslib.NewGroup()
			group2.Name = "development"
			return []*gokeepasslib.Group{&group1, &group2}, nil
		}
		return []*gokeepasslib.Group{}, nil
	}

	environments := map[string][]secrets.SecretItem{
		"development": {
			{
				Name:  "TEST_ITEM",
				Type:  "envvar",
				Entry: "TEST_ENTRY",
				Key:   "Password",
			},
		},
	}

	// This should fail due to duplicate environment
	_, err := manager.EnsureProfileStructure("test.kdbx", "test.keyfile", "password", "test_profile", environments)
	if err == nil {
		t.Error("Expected error for duplicate environment, got nil")
	}

	expectedError := "duplicate environment detected: 'development' found 2 times in profile/HEAD"
	if !contains(err.Error(), expectedError) {
		t.Errorf("Expected error message to contain '%s', got '%s'", expectedError, err.Error())
	}
}

func TestSecretsManager_DuplicateEntryDetection(t *testing.T) {
	// Create mock with duplicate entries
	mockDB := NewMockDatabaseManagerForEntries()
	mockLogger := logger.NewLogger(false)
	manager := secrets.NewSecretsManager(mockDB, mockLogger, nil, nil)

	// Simulate finding duplicate entries
	mockDB.FindEntriesByTitleFunc = func(group *gokeepasslib.Group, entryTitle string) []*gokeepasslib.Entry {
		if entryTitle == "TEST_ENTRY" {
			// Return 2 entries to simulate duplicate
			entry1 := gokeepasslib.NewEntry()
			entry2 := gokeepasslib.NewEntry()
			return []*gokeepasslib.Entry{&entry1, &entry2}
		}
		return []*gokeepasslib.Entry{}
	}

	environments := map[string][]secrets.SecretItem{
		"development": {
			{
				Name:  "TEST_ITEM",
				Type:  "envvar",
				Entry: "TEST_ENTRY",
				Key:   "Password",
			},
		},
	}

	// This should fail due to duplicate entry
	_, err := manager.EnsureProfileStructure("test.kdbx", "test.keyfile", "password", "test_profile", environments)
	if err == nil {
		t.Error("Expected error for duplicate entry, got nil")
	}

	expectedError := "duplicate entry detected: 'TEST_ENTRY' found 2 times in environment 'development'"
	if !contains(err.Error(), expectedError) {
		t.Errorf("Expected error message to contain '%s', got '%s'", expectedError, err.Error())
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		(len(s) > len(substr) && strings.Contains(s, substr))
}
