package secrets_test

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/secrets/common"
	"github.com/Yohnah/secrets/internal/template"
	"github.com/Yohnah/secrets/internal/validator"
	"github.com/tobischo/gokeepasslib/v3"
	"gopkg.in/yaml.v3"
)

// Global state for mock password validation across test instances
var mockExpectedPassword string
var mockPasswordsByDB map[string]string

func init() {
	mockPasswordsByDB = make(map[string]string)
}

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
	openCalled             bool
	saveAndCloseCalled     bool
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
	// Check if we have a stored password for this database
	expectedPassword, hasStoredPassword := mockPasswordsByDB[dbPath]
	if !hasStoredPassword {
		// Fall back to environment variable
		expectedPassword = os.Getenv("SECRETS_YOHNAH_PASSWORD")
		if expectedPassword == "" {
			expectedPassword = "TestPassword123!" // fallback
		}
	}
	if password != expectedPassword {
		return fmt.Errorf("invalid password")
	}
	if m.openError != nil {
		return m.openError
	}
	// Initialize a basic database structure for testing
	if m.db == nil {
		m.db = &gokeepasslib.Database{
			Content: &gokeepasslib.DBContent{
				Root: &gokeepasslib.RootData{
					Groups: []gokeepasslib.Group{
						{Name: "Root", Groups: []gokeepasslib.Group{}},
					},
				},
			},
		}
	}
	m.isOpen = true
	return nil
}

func (m *mockKeePassManager) SaveAndClose() error {
	m.saveAndCloseCalled = true
	if m.saveError != nil {
		return m.saveError
	}
	// Update profiles map based on current database structure
	if m.db != nil && m.db.Content != nil && m.db.Content.Root != nil {
		// Clear existing profiles
		m.profiles = make(map[string]bool)
		// Update from database structure
		for _, group := range m.db.Content.Root.Groups[0].Groups {
			m.profiles[group.Name] = true
		}
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
	// Set the expected password for this database path
	mockPasswordsByDB[dbPath] = password

	// Initialize database structure with the custom root group name
	m.db = &gokeepasslib.Database{
		Content: &gokeepasslib.DBContent{
			Root: &gokeepasslib.RootData{
				Groups: []gokeepasslib.Group{
					{Name: rootGroupName, Groups: []gokeepasslib.Group{}},
				},
			},
		},
	}

	// Create dummy database file
	file, err := os.Create(dbPath)
	if err != nil {
		return err
	}
	file.WriteString("dummy database content")
	file.Close()
	return nil
}

func (m *mockKeePassManager) GenerateKeyfile(keyfilePath string) error {
	// Create dummy keyfile with correct size (64 bytes) and permissions
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i % 256)
	}
	err := os.WriteFile(keyfilePath, data, 0600)
	return err
}

func (m *mockKeePassManager) CreateProfile(profileName string) error {
	// Check if profile already exists (idempotent operation)
	if m.profiles[profileName] {
		return nil // Profile already exists
	}

	m.profiles[profileName] = true
	m.treeGroups[profileName] = []string{"HEAD"}
	m.treeGroupExists[profileName+"/HEAD"] = true
	// Set default HEAD metadata
	m.treeGroupFields[profileName+"/HEAD/metadata/version"] = "1"
	m.treeGroupFields[profileName+"/HEAD/metadata/datetime"] = time.Now().UTC().Format(time.RFC3339)

	// If database is initialized, add the profile structure
	if m.db != nil && m.db.Content != nil && m.db.Content.Root != nil {
		// Check if profile already exists in database structure
		for _, group := range m.db.Content.Root.Groups[0].Groups {
			if group.Name == profileName {
				return nil // Profile already exists
			}
		}

		// Create metadata entry
		metadataEntry := gokeepasslib.NewEntry()
		metadataEntry.Values = []gokeepasslib.ValueData{
			{Key: "Title", Value: gokeepasslib.V{Content: "metadata"}},
			{Key: "version", Value: gokeepasslib.V{Content: "1"}},
			{Key: "datetime", Value: gokeepasslib.V{Content: time.Now().UTC().Format(time.RFC3339)}},
		}

		headGroup := gokeepasslib.Group{
			Name:    "HEAD",
			Entries: []gokeepasslib.Entry{metadataEntry},
		}
		profileGroup := gokeepasslib.Group{
			Name:   profileName,
			Groups: []gokeepasslib.Group{headGroup},
		}
		m.db.Content.Root.Groups[0].Groups = append(m.db.Content.Root.Groups[0].Groups, profileGroup)
	}

	return nil
}

func (m *mockKeePassManager) ProfileExists(profileName string) (bool, error) {
	// First check the database structure if available
	if m.db != nil && m.db.Content != nil && m.db.Content.Root != nil {
		for _, group := range m.db.Content.Root.Groups[0].Groups {
			if group.Name == profileName {
				return true, nil
			}
		}
	}
	// Fall back to the internal map
	return m.profiles[profileName], nil
}

func (m *mockKeePassManager) CreateGroup(profileName, parentGroupName, groupName string) (bool, error) {
	// Add to tree groups if it's a tree group (environment)
	if parentGroupName == "HEAD" {
		if groups, ok := m.treeGroups[profileName]; ok {
			// Check if already exists
			for _, g := range groups {
				if g == groupName {
					return false, nil // already exists
				}
			}
			m.treeGroups[profileName] = append(groups, groupName)
			m.treeGroupExists[profileName+"/"+groupName] = true
		}
	}

	// If database is initialized, add the group structure
	if m.db != nil && m.db.Content != nil && m.db.Content.Root != nil {
		// Find the profile group
		for i := range m.db.Content.Root.Groups[0].Groups {
			profileGroup := &m.db.Content.Root.Groups[0].Groups[i]
			if profileGroup.Name == profileName {
				// Find the parent group (HEAD)
				for j := range profileGroup.Groups {
					if profileGroup.Groups[j].Name == parentGroupName {
						// Add the new group
						newGroup := gokeepasslib.Group{Name: groupName}
						profileGroup.Groups[j].Groups = append(profileGroup.Groups[j].Groups, newGroup)
						break
					}
				}
				break
			}
		}
	}

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
	// Mock implementation that returns expected entries for test-create-entries profile
	if profileName == "test-create-entries" {
		switch envName {
		case "production":
			return []string{"DB", "API"}, nil
		case "staging":
			return []string{"DB"}, nil
		}
	}
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

func (m *mockKeePassManager) GetFieldValue(profileName, envName, entryPath, fieldName string) (string, error) {
	// Simple mock implementation: return empty string (simulating empty field)
	// Tests can be extended later if they need specific field values
	return "", nil
}

func (m *mockKeePassManager) GetAttachmentContent(profileName, envName, entryPath, attachmentName string) ([]byte, error) {
	// Simple mock implementation: return empty byte slice
	// Tests can be extended later if they need specific attachment content
	return []byte{}, nil
}

func (m *mockKeePassManager) ListProfileTreeGroups(profileName string) ([]string, error) {
	if groups, ok := m.treeGroups[profileName]; ok {
		return groups, nil
	}
	return []string{}, nil
}

func (m *mockKeePassManager) GetTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName string) (*common.SecureValue, error) {
	key := profileName + "/" + treeGroup + "/" + entryPath + "/" + fieldName
	if value, ok := m.treeGroupFields[key]; ok {
		return common.NewSecureValue(value), nil
	}
	return nil, nil
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

	// If database is initialized, add the profile structure
	if m.db != nil && m.db.Content != nil && m.db.Content.Root != nil {
		headGroup := gokeepasslib.Group{Name: "HEAD"}
		profileGroup := gokeepasslib.Group{
			Name:   profileName,
			Groups: []gokeepasslib.Group{headGroup},
		}
		m.db.Content.Root.Groups[0].Groups = append(m.db.Content.Root.Groups[0].Groups, profileGroup)
	}
}

func (m *mockKeePassManager) GetRootGroups() ([]string, error) {
	if !m.isOpen {
		return nil, fmt.Errorf("database not open")
	}
	if m.db == nil || len(m.db.Content.Root.Groups) == 0 {
		return []string{}, nil
	}
	var groups []string
	for _, g := range m.db.Content.Root.Groups[0].Groups {
		groups = append(groups, g.Name)
	}
	return groups, nil
}

func (m *mockKeePassManager) GetGroupsByParent(parentPath string) ([]string, error) {
	if !m.isOpen {
		return nil, fmt.Errorf("database not open")
	}
	// Simple implementation for testing
	if parentPath == "" {
		return m.GetRootGroups()
	}
	// For profiles, return tree groups
	if groups, ok := m.treeGroups[parentPath]; ok {
		return groups, nil
	}
	return []string{}, nil
}

func (m *mockKeePassManager) GetEntriesByGroup(groupPath string) ([]string, error) {
	if !m.isOpen {
		return nil, fmt.Errorf("database not open")
	}
	// Simple implementation - return empty for testing
	return []string{}, nil
}

func (m *mockKeePassManager) GetFieldsByEntry(entryPath string) ([]string, error) {
	if !m.isOpen {
		return nil, fmt.Errorf("database not open")
	}
	// Simple implementation - return empty for testing
	return []string{}, nil
}

func (m *mockKeePassManager) GetFieldsByEnvironmentEntry(profileName, envName, entryPath string) ([]string, error) {
	if !m.isOpen {
		return nil, fmt.Errorf("database not open")
	}
	// Simple implementation - return empty for testing
	return []string{}, nil
}

func (m *mockKeePassManager) GetAllFieldsByEnvironmentEntry(profileName, envName, entryPath string) ([]string, error) {
	if !m.isOpen {
		return nil, fmt.Errorf("database not open")
	}
	// Simple implementation - return empty for testing
	return []string{}, nil
}

// mockConfigManager is a mock implementation of config.Manager for testing
type mockConfigManager struct {
	secretsFilePath string
}

func newMockConfigManager(secretsFilePath string) *mockConfigManager {
	return &mockConfigManager{
		secretsFilePath: secretsFilePath,
	}
}

func (m *mockConfigManager) GetConfig() (*config.Config, error) {
	return &config.Config{}, nil
}

func (m *mockConfigManager) CreateDefaultConfig(path string) error {
	return nil
}

func (m *mockConfigManager) CreateDefaultConfigWithNoCreate(path string, noCreateDatabase bool) error {
	return nil
}

func (m *mockConfigManager) GetDatabasePath() string {
	return "/tmp/test.db"
}

func (m *mockConfigManager) GetKeyfilePath() string {
	return "/tmp/test.key"
}

func (m *mockConfigManager) GetSecretsFilePath() string {
	return m.secretsFilePath
}

func (m *mockConfigManager) ShouldIgnoreConfigFile() bool {
	return false
}

func (m *mockConfigManager) ShouldIgnoreGitProject() bool {
	return true
}

func (m *mockConfigManager) ShouldUseHomeDirectory() bool {
	return false
}

func (m *mockConfigManager) GetPassword() (string, error) {
	return "TestPassword123!", nil
}

func (m *mockConfigManager) IsNoInteractive() bool {
	return false
}

func (m *mockConfigManager) GenerateSecurePassword() string {
	return "TestPassword123!"
}

// mockValidatorManager is a mock implementation of validator.ValidatorManager for testing
type mockValidatorManager struct {
	secretsContent string
}

func newMockValidatorManager(secretsContent string) *mockValidatorManager {
	return &mockValidatorManager{
		secretsContent: secretsContent,
	}
}

func (m *mockValidatorManager) ReadAndValidateSecretsYML(path string) (*validator.SecretsConfig, []error) {
	// Parse the YAML content using the same logic as the real validator
	profiles, parseErrors := m.parseMultiDocumentYAML([]byte(m.secretsContent))
	if len(parseErrors) > 0 {
		return nil, parseErrors
	}

	// Return successful configuration
	config := &validator.SecretsConfig{
		Profiles: profiles,
	}

	return config, nil
}

// parseMultiDocumentYAML parses a YAML file with multiple documents (separated by ---)
func (m *mockValidatorManager) parseMultiDocumentYAML(data []byte) ([]validator.Profile, []error) {
	var profiles []validator.Profile
	var errors []error

	decoder := yaml.NewDecoder(strings.NewReader(string(data)))

	docIndex := 0
	for {
		var profile validator.Profile
		err := decoder.Decode(&profile)
		if err != nil {
			// EOF is expected when no more documents
			if err.Error() == "EOF" {
				break
			}
			errors = append(errors, fmt.Errorf("failed to parse YAML document %d: %w", docIndex+1, err))
			return nil, errors
		}

		profiles = append(profiles, profile)
		docIndex++
	}

	// At least one profile must exist
	if len(profiles) == 0 {
		errors = append(errors, fmt.Errorf("secrets.yml must contain at least one profile"))
		return nil, errors
	}

	return profiles, nil
}

func (m *mockValidatorManager) ValidateConfigFile(path string) error {
	return nil
}

func (m *mockValidatorManager) ValidateTemplate(template string) error {
	return nil
}

func (m *mockValidatorManager) ValidateSecretsYML(config *validator.SecretsConfig) []error {
	return nil
}

func (m *mockValidatorManager) ValidateKeePassDuplicates(db validator.KeePassManager) []error {
	return nil
}

func (m *mockValidatorManager) ValidateNoDuplicateEntries(envName string, entryPaths []string) error {
	return nil
}

func (m *mockValidatorManager) ValidateUniqueProfileInRoot(profiles []string, profileName string) error {
	return nil
}

func (m *mockValidatorManager) ValidateUniqueEntryInPath(entries []string, entryName string, fullPath string) error {
	return nil
}

func (m *mockValidatorManager) ValidateUniqueFieldsInEntry(fields []string, entryPath string) error {
	return nil
}

// newMockTemplateManager creates a new template.Manager for testing
func newMockTemplateManager() template.Manager {
	return template.NewManager()
}
