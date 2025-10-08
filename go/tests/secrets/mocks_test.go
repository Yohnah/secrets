package secrets_test

import (
	"time"

	"github.com/tobischo/gokeepasslib/v3"
)

// mockKeePassManager is a mock implementation of keepass.Manager for testing
type mockKeePassManager struct {
	// Database state
	db              *gokeepasslib.Database
	isOpen          bool
	openError       error
	saveError       error
	profiles        map[string]bool
	treeGroups      map[string][]string // profileName -> []treeGroupNames
	treeGroupFields map[string]string   // "profile/treeGroup/entry/field" -> value
	treeGroupExists map[string]bool     // "profile/treeGroup" -> exists

	// Call tracking
	openCalled         bool
	saveAndCloseCalled bool
	closeWithoutSaveCalled bool
}

func newMockKeePassManager() *mockKeePassManager {
	return &mockKeePassManager{
		profiles:        make(map[string]bool),
		treeGroups:      make(map[string][]string),
		treeGroupFields: make(map[string]string),
		treeGroupExists: make(map[string]bool),
		isOpen:          false,
	}
}

func (m *mockKeePassManager) Open(dbPath, keyfilePath, password string) error {
	m.openCalled = true
	if m.openError != nil {
		return m.openError
	}
	m.isOpen = true
	return nil
}

func (m *mockKeePassManager) SaveAndClose() error {
	m.saveAndCloseCalled = true
	if m.saveError != nil {
		return m.saveError
	}
	m.isOpen = false
	return nil
}

func (m *mockKeePassManager) CloseWithoutSave() error {
	m.closeWithoutSaveCalled = true
	m.isOpen = false
	return nil
}

func (m *mockKeePassManager) IsOpen() bool {
	return m.isOpen
}

func (m *mockKeePassManager) GetDatabase() *gokeepasslib.Database {
	return m.db
}

func (m *mockKeePassManager) CreateDatabase(dbPath, keyfilePath, password, rootGroupName string) error {
	return nil
}

func (m *mockKeePassManager) GenerateKeyfile(keyfilePath string) error {
	return nil
}

func (m *mockKeePassManager) CreateProfile(profileName string) error {
	m.profiles[profileName] = true
	m.treeGroups[profileName] = []string{"HEAD"}
	m.treeGroupExists[profileName+"/HEAD"] = true
	// Set default HEAD metadata
	m.treeGroupFields[profileName+"/HEAD/metadata/version"] = "1"
	m.treeGroupFields[profileName+"/HEAD/metadata/datetime"] = time.Now().UTC().Format(time.RFC3339)
	return nil
}

func (m *mockKeePassManager) ProfileExists(profileName string) (bool, error) {
	return m.profiles[profileName], nil
}

func (m *mockKeePassManager) CreateGroup(profileName, parentGroupName, groupName string) (bool, error) {
	return true, nil
}

func (m *mockKeePassManager) GroupExists(profileName, parentGroupName, groupName string) (bool, error) {
	return false, nil
}

func (m *mockKeePassManager) CreateEntry(profileName, envName, entryPath string) error {
	return nil
}

func (m *mockKeePassManager) EntryExists(profileName, envName, entryPath string) (bool, error) {
	return false, nil
}

func (m *mockKeePassManager) GetEntriesByEnvironment(profileName, envName string) ([]string, error) {
	return []string{}, nil
}

func (m *mockKeePassManager) IsStandardField(fieldName string) bool {
	return false
}

func (m *mockKeePassManager) SetStandardField(profileName, envName, entryPath, fieldName, value string) error {
	return nil
}

func (m *mockKeePassManager) SetCustomField(profileName, envName, entryPath, fieldName, value string) error {
	return nil
}

func (m *mockKeePassManager) CreateAttachment(profileName, envName, entryPath, attachmentName string, data []byte) error {
	return nil
}

func (m *mockKeePassManager) FieldExists(profileName, envName, entryPath, fieldName string) (bool, error) {
	return false, nil
}

func (m *mockKeePassManager) ListProfileTreeGroups(profileName string) ([]string, error) {
	if groups, ok := m.treeGroups[profileName]; ok {
		return groups, nil
	}
	return []string{}, nil
}

func (m *mockKeePassManager) GetTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName string) (string, error) {
	key := profileName + "/" + treeGroup + "/" + entryPath + "/" + fieldName
	if value, ok := m.treeGroupFields[key]; ok {
		return value, nil
	}
	return "", nil
}

func (m *mockKeePassManager) CloneTreeGroup(profileName, sourceTreeGroup, targetTreeGroup string) error {
	// Copy all fields from source to target
	for key, value := range m.treeGroupFields {
		if len(key) > len(profileName+"/"+sourceTreeGroup+"/") &&
			key[:len(profileName+"/"+sourceTreeGroup+"/")] == profileName+"/"+sourceTreeGroup+"/" {
			newKey := profileName + "/" + targetTreeGroup + "/" + key[len(profileName+"/"+sourceTreeGroup+"/"):]
			m.treeGroupFields[newKey] = value
		}
	}
	
	// Add to tree groups list
	if groups, ok := m.treeGroups[profileName]; ok {
		m.treeGroups[profileName] = append(groups, targetTreeGroup)
	}
	m.treeGroupExists[profileName+"/"+targetTreeGroup] = true
	
	return nil
}

func (m *mockKeePassManager) SetTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName, value string) error {
	key := profileName + "/" + treeGroup + "/" + entryPath + "/" + fieldName
	m.treeGroupFields[key] = value
	return nil
}

func (m *mockKeePassManager) TreeGroupExists(profileName, treeGroup string) (bool, error) {
	key := profileName + "/" + treeGroup
	return m.treeGroupExists[key], nil
}

func (m *mockKeePassManager) RenameTreeGroup(profileName, oldName, newName string) error {
	// Update tree groups list
	if groups, ok := m.treeGroups[profileName]; ok {
		for i, group := range groups {
			if group == oldName {
				m.treeGroups[profileName][i] = newName
				break
			}
		}
	}
	
	// Update exists map
	delete(m.treeGroupExists, profileName+"/"+oldName)
	m.treeGroupExists[profileName+"/"+newName] = true
	
	// Rename all fields
	newFields := make(map[string]string)
	for key, value := range m.treeGroupFields {
		if len(key) > len(profileName+"/"+oldName+"/") &&
			key[:len(profileName+"/"+oldName+"/")] == profileName+"/"+oldName+"/" {
			newKey := profileName + "/" + newName + "/" + key[len(profileName+"/"+oldName+"/"):]
			newFields[newKey] = value
		} else {
			newFields[key] = value
		}
	}
	m.treeGroupFields = newFields
	
	return nil
}

func (m *mockKeePassManager) DeleteTreeGroup(profileName, treeGroup string) error {
	// Remove from tree groups list
	if groups, ok := m.treeGroups[profileName]; ok {
		for i, group := range groups {
			if group == treeGroup {
				m.treeGroups[profileName] = append(groups[:i], groups[i+1:]...)
				break
			}
		}
	}
	
	// Remove from exists map
	delete(m.treeGroupExists, profileName+"/"+treeGroup)
	
	// Delete all fields
	for key := range m.treeGroupFields {
		if len(key) > len(profileName+"/"+treeGroup+"/") &&
			key[:len(profileName+"/"+treeGroup+"/")] == profileName+"/"+treeGroup+"/" {
			delete(m.treeGroupFields, key)
		}
	}
	
	return nil
}

// Helper method to set up a profile with snapshots
func (m *mockKeePassManager) setupProfileWithSnapshots(profileName string, versions []string) {
	m.profiles[profileName] = true
	m.treeGroups[profileName] = append([]string{"HEAD"}, versions...)
	
	// Set HEAD
	m.treeGroupExists[profileName+"/HEAD"] = true
	currentVersion := len(versions) + 1
	m.treeGroupFields[profileName+"/HEAD/metadata/version"] = string(rune('0' + currentVersion))
	m.treeGroupFields[profileName+"/HEAD/metadata/datetime"] = time.Now().UTC().Format(time.RFC3339)
	
	// Set versions
	for i, version := range versions {
		m.treeGroupExists[profileName+"/"+version] = true
		m.treeGroupFields[profileName+"/"+version+"/metadata/version"] = string(rune('0' + i + 1))
		m.treeGroupFields[profileName+"/"+version+"/metadata/datetime"] = time.Now().Add(-time.Hour * time.Duration(len(versions)-i)).UTC().Format(time.RFC3339)
	}
}
