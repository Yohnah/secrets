package secrets_test

import (
	"testing"

	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/tobischo/gokeepasslib/v3"
)

// MockDatabaseManager implements secrets.DatabaseManager for testing
type MockDatabaseManager struct {
	createCalled      bool
	existsCalled      bool
	generateKeyCalled bool
}

func (m *MockDatabaseManager) Create(dbPath, keyfilePath, password string) error {
	m.createCalled = true
	return nil
}

func (m *MockDatabaseManager) Exists(dbPath string) bool {
	m.existsCalled = true
	return false
}

func (m *MockDatabaseManager) GenerateKeyfile(keyfilePath string) error {
	m.generateKeyCalled = true
	return nil
}

// New CRUD methods for MockDatabaseManager
func (m *MockDatabaseManager) OpenDatabase(dbPath, keyfilePath, password string) (*gokeepasslib.Database, error) {
	return gokeepasslib.NewDatabase(), nil
}

func (m *MockDatabaseManager) SaveDatabase(db *gokeepasslib.Database, dbPath string) error {
	return nil
}

func (m *MockDatabaseManager) Open(dbPath, keyfilePath, password string) (*gokeepasslib.Database, error) {
	return gokeepasslib.NewDatabase(), nil
}

func (m *MockDatabaseManager) Save(db *gokeepasslib.Database, dbPath, keyfilePath, password string) error {
	return nil
}

func (m *MockDatabaseManager) FindGroupsByName(db *gokeepasslib.Database, groupName string) ([]*gokeepasslib.Group, error) {
	return []*gokeepasslib.Group{}, nil
}

func (m *MockDatabaseManager) FindGroupsByNameInParent(parentGroup *gokeepasslib.Group, groupName string) ([]*gokeepasslib.Group, error) {
	return []*gokeepasslib.Group{}, nil
}

func (m *MockDatabaseManager) CreateGroup(parentGroup *gokeepasslib.Group, groupName string) *gokeepasslib.Group {
	newGroup := gokeepasslib.NewGroup()
	newGroup.Name = groupName
	return &newGroup
}

// New Entry CRUD methods for MockDatabaseManager
func (m *MockDatabaseManager) CreateEntry(parentGroup *gokeepasslib.Group, entryTitle string) *gokeepasslib.Entry {
	entry := gokeepasslib.NewEntry()
	return &entry
}

func (m *MockDatabaseManager) SetEntryField(entry *gokeepasslib.Entry, fieldName, fieldValue string) {
	// Mock implementation - no actual field setting needed for tests
}

func (m *MockDatabaseManager) FindEntriesByTitle(group *gokeepasslib.Group, entryTitle string) []*gokeepasslib.Entry {
	return []*gokeepasslib.Entry{}
}

func (m *MockDatabaseManager) CreateGroupChain(parentGroup *gokeepasslib.Group, pathSegments []string) *gokeepasslib.Group {
	return parentGroup // Mock implementation - just return parent for simplicity
}

func (m *MockDatabaseManager) CloneGroup(sourceGroup *gokeepasslib.Group, newName string) (*gokeepasslib.Group, error) {
	newGroup := gokeepasslib.NewGroup()
	newGroup.Name = newName
	return &newGroup, nil
}

func (m *MockDatabaseManager) DeleteGroup(parentGroup *gokeepasslib.Group, groupName string) error {
	return nil // Mock implementation
}

// Attachment methods for MockDatabaseManager
func (m *MockDatabaseManager) AddAttachment(db *gokeepasslib.Database, entry *gokeepasslib.Entry, filename string, content []byte) error {
	// Mock implementation - just add to entry's Binaries slice
	binaryRef := gokeepasslib.BinaryReference{Name: filename}
	entry.Binaries = append(entry.Binaries, binaryRef)
	return nil
}

func (m *MockDatabaseManager) HasAttachment(entry *gokeepasslib.Entry, filename string) bool {
	// Mock implementation - check in entry's Binaries slice
	for _, binRef := range entry.Binaries {
		if binRef.Name == filename {
			return true
		}
	}
	return false
}

func (m *MockDatabaseManager) ListAttachments(entry *gokeepasslib.Entry) []string {
	// Mock implementation - return filenames from entry's Binaries slice
	var filenames []string
	for _, binRef := range entry.Binaries {
		filenames = append(filenames, binRef.Name)
	}
	return filenames
}

func TestNewSecretsManager(t *testing.T) {
	mockDB := &MockDatabaseManager{}
	mockLogger := logger.NewLogger(false)
	manager := secrets.NewSecretsManager(mockDB, mockLogger, nil, nil)

	if manager == nil {
		t.Error("Expected SecretsManager to be created, got nil")
	}

	// Test interface compliance
	var _ secrets.SecretsManager = manager
}

func TestBasicSecretsManagerOperation(t *testing.T) {
	mockDB := &MockDatabaseManager{}
	mockLogger := logger.NewLogger(false)
	manager := secrets.NewSecretsManager(mockDB, mockLogger, nil, nil)

	if manager == nil {
		t.Error("Expected SecretsManager to be created, got nil")
	}

	// Test that the manager was created successfully
	// More detailed tests would require implementing specific business logic methods
}
