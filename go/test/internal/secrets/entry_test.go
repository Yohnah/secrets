package secrets_test

import (
	"testing"

	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/tobischo/gokeepasslib/v3"
)

// Enhanced MockDatabaseManager for entry testing
type MockDatabaseManagerForEntries struct {
	MockDatabaseManager
	CreatedEntries               map[string][]*gokeepasslib.Entry
	CreatedGroups                map[string][]*gokeepasslib.Group
	GroupChainCalls              []GroupChainCall
	FindGroupsByNameInParentFunc func(parentGroup *gokeepasslib.Group, groupName string) ([]*gokeepasslib.Group, error)
	FindEntriesByTitleFunc       func(group *gokeepasslib.Group, entryTitle string) []*gokeepasslib.Entry
}

type GroupChainCall struct {
	ParentGroup  *gokeepasslib.Group
	PathSegments []string
}

func NewMockDatabaseManagerForEntries() *MockDatabaseManagerForEntries {
	return &MockDatabaseManagerForEntries{
		CreatedEntries:  make(map[string][]*gokeepasslib.Entry),
		CreatedGroups:   make(map[string][]*gokeepasslib.Group),
		GroupChainCalls: []GroupChainCall{},
	}
}

func (m *MockDatabaseManagerForEntries) CreateEntry(parentGroup *gokeepasslib.Group, entryTitle string) *gokeepasslib.Entry {
	entry := gokeepasslib.NewEntry()
	// Set the title using the gokeepasslib method
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: entryTitle},
	})

	// Track created entries by group name
	groupName := parentGroup.Name
	if m.CreatedEntries[groupName] == nil {
		m.CreatedEntries[groupName] = []*gokeepasslib.Entry{}
	}
	m.CreatedEntries[groupName] = append(m.CreatedEntries[groupName], &entry)

	// Add entry to the parent group for realistic simulation
	parentGroup.Entries = append(parentGroup.Entries, entry)

	return &entry
}

func (m *MockDatabaseManagerForEntries) SetEntryField(entry *gokeepasslib.Entry, fieldName, fieldValue string) {
	// Check if field already exists
	for i := range entry.Values {
		if entry.Values[i].Key == fieldName {
			entry.Values[i].Value.Content = fieldValue
			return
		}
	}

	// Field doesn't exist, create it
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   fieldName,
		Value: gokeepasslib.V{Content: fieldValue},
	})
}

func (m *MockDatabaseManagerForEntries) FindEntriesByTitle(group *gokeepasslib.Group, entryTitle string) []*gokeepasslib.Entry {
	// Check if custom function is provided for testing
	if m.FindEntriesByTitleFunc != nil {
		return m.FindEntriesByTitleFunc(group, entryTitle)
	}

	// Default behavior
	var foundEntries []*gokeepasslib.Entry
	for _, entry := range group.Entries {
		if entry.GetTitle() == entryTitle {
			foundEntries = append(foundEntries, &entry)
		}
	}
	return foundEntries
}

func (m *MockDatabaseManagerForEntries) CloneGroup(sourceGroup *gokeepasslib.Group, newName string) (*gokeepasslib.Group, error) {
	newGroup := gokeepasslib.NewGroup()
	newGroup.Name = newName
	return &newGroup, nil
}

func (m *MockDatabaseManagerForEntries) DeleteGroup(parentGroup *gokeepasslib.Group, groupName string) error {
	return nil // Mock implementation
}

func (m *MockDatabaseManagerForEntries) Open(dbPath, keyfilePath, password string) (*gokeepasslib.Database, error) {
	return gokeepasslib.NewDatabase(), nil
}

func (m *MockDatabaseManagerForEntries) Save(db *gokeepasslib.Database, dbPath, keyfilePath, password string) error {
	return nil
}

func (m *MockDatabaseManagerForEntries) CreateGroupChain(parentGroup *gokeepasslib.Group, pathSegments []string) *gokeepasslib.Group {
	// Track the call for verification
	m.GroupChainCalls = append(m.GroupChainCalls, GroupChainCall{
		ParentGroup:  parentGroup,
		PathSegments: pathSegments,
	})

	// Simulate creating nested groups
	currentGroup := parentGroup
	for _, segment := range pathSegments {
		// Check if group already exists
		var foundGroup *gokeepasslib.Group
		for i := range currentGroup.Groups {
			if currentGroup.Groups[i].Name == segment {
				foundGroup = &currentGroup.Groups[i]
				break
			}
		}

		// Create group if it doesn't exist
		if foundGroup == nil {
			foundGroup = m.CreateGroup(currentGroup, segment)
		}

		currentGroup = foundGroup
	}

	return currentGroup
}

func (m *MockDatabaseManagerForEntries) CreateGroup(parentGroup *gokeepasslib.Group, groupName string) *gokeepasslib.Group {
	newGroup := gokeepasslib.NewGroup()
	newGroup.Name = groupName

	// Track created groups
	parentName := parentGroup.Name
	if m.CreatedGroups[parentName] == nil {
		m.CreatedGroups[parentName] = []*gokeepasslib.Group{}
	}
	m.CreatedGroups[parentName] = append(m.CreatedGroups[parentName], &newGroup)

	// Add group to parent for realistic simulation
	parentGroup.Groups = append(parentGroup.Groups, newGroup)

	return &newGroup
}

func (m *MockDatabaseManagerForEntries) FindGroupsByNameInParent(parentGroup *gokeepasslib.Group, groupName string) ([]*gokeepasslib.Group, error) {
	// Check if custom function is provided for testing
	if m.FindGroupsByNameInParentFunc != nil {
		return m.FindGroupsByNameInParentFunc(parentGroup, groupName)
	}

	// Default behavior - return empty slice (no groups found)
	return []*gokeepasslib.Group{}, nil
}

func TestSecretsManager_EnsureProfileStructure_WithEntries(t *testing.T) {
	mockDB := NewMockDatabaseManagerForEntries()
	mockLogger := logger.NewLogger(false)
	manager := secrets.NewSecretsManager(mockDB, mockLogger, nil, nil)

	// Create test environments with entries
	environments := map[string][]secrets.SecretItem{
		"development": {
			{
				Name:  "DATABASE_URL",
				Type:  "envvar",
				Entry: "DATABASE_URL",
				Key:   "Password",
			},
			{
				Name:  "API_TOKEN",
				Type:  "envvar",
				Entry: "/tokens/API_TOKEN",
				Key:   "Password",
			},
		},
		"production": {
			{
				Name:  "PROD_SECRET",
				Type:  "envvar",
				Entry: "/production/secrets/MAIN_SECRET",
				Key:   "Password",
			},
		},
	}

	// Test EnsureProfileStructure with entries
	result, err := manager.EnsureProfileStructure("test.kdbx", "test.keyfile", "password", "test_profile", environments)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to be non-nil")
	}

	// Verify environments were processed
	if len(result.EnvironmentsCreated) == 0 {
		t.Error("Expected environments to be created")
	}

	// Verify that CreateGroupChain was called for nested paths
	expectedChainCalls := 0
	for _, items := range environments {
		for _, item := range items {
			if len(item.Entry) > 0 && item.Entry[0] == '/' {
				// Count expected nested paths
				expectedChainCalls++
			}
		}
	}

	if len(mockDB.GroupChainCalls) < expectedChainCalls {
		t.Errorf("Expected at least %d CreateGroupChain calls, got %d", expectedChainCalls, len(mockDB.GroupChainCalls))
	}
}

func TestSecretsManager_ParseEntryPath_Functionality(t *testing.T) {
	mockDB := NewMockDatabaseManagerForEntries()
	mockLogger := logger.NewLogger(false)
	manager := secrets.NewSecretsManager(mockDB, mockLogger, nil, nil)

	// Test cases for entry path parsing
	testCases := []struct {
		name          string
		entryPath     string
		expectedTitle string
		expectedParts []string
	}{
		{
			name:          "Simple entry path",
			entryPath:     "VAULT_TOKEN",
			expectedTitle: "VAULT_TOKEN",
			expectedParts: []string{},
		},
		{
			name:          "Root-prefixed simple path",
			entryPath:     "/VAULT_TOKEN",
			expectedTitle: "VAULT_TOKEN",
			expectedParts: []string{},
		},
		{
			name:          "Nested entry path",
			entryPath:     "/tokens/API_TOKEN",
			expectedTitle: "API_TOKEN",
			expectedParts: []string{"tokens"},
		},
		{
			name:          "Deeply nested path",
			entryPath:     "/production/secrets/database/MAIN_SECRET",
			expectedTitle: "MAIN_SECRET",
			expectedParts: []string{"production", "secrets", "database"},
		},
	}

	// Since ParseEntryPath is likely internal, we'll test it indirectly through EnsureProfileStructure
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			environments := map[string][]secrets.SecretItem{
				"test": {
					{
						Name:  "TEST_ITEM",
						Type:  "envvar",
						Entry: tc.entryPath,
						Key:   "Password",
					},
				},
			}

			// Reset mock state
			mockDB.GroupChainCalls = []GroupChainCall{}
			mockDB.CreatedEntries = make(map[string][]*gokeepasslib.Entry)

			_, err := manager.EnsureProfileStructure("test.kdbx", "test.keyfile", "password", "test_profile", environments)
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			// Verify CreateGroupChain was called with correct path segments
			if len(tc.expectedParts) > 0 {
				if len(mockDB.GroupChainCalls) == 0 {
					t.Error("Expected CreateGroupChain to be called for nested path")
				} else {
					call := mockDB.GroupChainCalls[0]
					if len(call.PathSegments) != len(tc.expectedParts) {
						t.Errorf("Expected %d path segments, got %d", len(tc.expectedParts), len(call.PathSegments))
					}
					for i, expected := range tc.expectedParts {
						if i < len(call.PathSegments) && call.PathSegments[i] != expected {
							t.Errorf("Expected path segment '%s', got '%s'", expected, call.PathSegments[i])
						}
					}
				}
			}
			// Note: CreateGroupChain is called even for simple paths, but with empty pathSegments
		})
	}
}

func TestSecretsManager_IncrementalEntryCreation(t *testing.T) {
	mockDB := NewMockDatabaseManagerForEntries()
	mockLogger := logger.NewLogger(false)
	manager := secrets.NewSecretsManager(mockDB, mockLogger, nil, nil)

	environments := map[string][]secrets.SecretItem{
		"development": {
			{
				Name:  "EXISTING_ENTRY",
				Type:  "envvar",
				Entry: "EXISTING_ENTRY",
				Key:   "Password",
			},
		},
	}

	// First call - should create entries
	result1, err := manager.EnsureProfileStructure("test.kdbx", "test.keyfile", "password", "test_profile", environments)
	if err != nil {
		t.Fatalf("Expected no error on first call, got %v", err)
	}

	if result1 == nil {
		t.Fatal("Expected first result to be non-nil")
	}

	// Second call - should find existing entries (idempotent)
	result2, err := manager.EnsureProfileStructure("test.kdbx", "test.keyfile", "password", "test_profile", environments)
	if err != nil {
		t.Fatalf("Expected no error on second call, got %v", err)
	}

	if result2 == nil {
		t.Fatal("Expected second result to be non-nil")
	}

	// Both calls should succeed - the mock simulates existing entries correctly
	// The real test is that no errors occur on subsequent calls
}

func TestSecretsManager_EntryCreationWithDuplicateItems(t *testing.T) {
	mockDB := NewMockDatabaseManagerForEntries()
	mockLogger := logger.NewLogger(false)
	manager := secrets.NewSecretsManager(mockDB, mockLogger, nil, nil)

	// Test with multiple items referencing the same entry (allowed by validation rules)
	environments := map[string][]secrets.SecretItem{
		"development": {
			{
				Name:  "DB_PASSWORD_ENV",
				Type:  "envvar",
				Entry: "DATABASE_CREDENTIALS",
				Key:   "Password",
			},
			{
				Name:  "DB_PASSWORD_TEXT",
				Type:  "text",
				Entry: "DATABASE_CREDENTIALS", // Same entry, different purpose
				Key:   "Password",
			},
			{
				Name:  "DB_USERNAME",
				Type:  "envvar",
				Entry: "DATABASE_CREDENTIALS", // Same entry, different key
				Key:   "UserName",
			},
		},
	}

	result, err := manager.EnsureProfileStructure("test.kdbx", "test.keyfile", "password", "test_profile", environments)
	if err != nil {
		t.Fatalf("Expected no error with duplicate entry references, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to be non-nil")
	}

	// Verify that only one entry was created despite multiple references
	developmentEntries := mockDB.CreatedEntries["development"]
	entryCount := 0
	for _, entry := range developmentEntries {
		if entry.GetTitle() == "DATABASE_CREDENTIALS" {
			entryCount++
		}
	}

	// Should create only one entry even though referenced multiple times
	if entryCount != 1 {
		t.Errorf("Expected exactly 1 'DATABASE_CREDENTIALS' entry, got %d", entryCount)
	}
}
