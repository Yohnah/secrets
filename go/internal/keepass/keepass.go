package keepass

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/tobischo/gokeepasslib/v3"
)

// DatabaseManager handles KeePass database operations
// Following SRP and ISP - Interface Segregation Principle
type DatabaseManager interface {
	// Database lifecycle operations
	Create(dbPath, keyfilePath, password string) error
	Exists(dbPath string) bool
	GenerateKeyfile(keyfilePath string) error

	// Database access operations
	OpenDatabase(dbPath, keyfilePath, password string) (*gokeepasslib.Database, error)
	SaveDatabase(db *gokeepasslib.Database, dbPath string) error
	Open(dbPath, keyfilePath, password string) (*gokeepasslib.Database, error)  // Alias for OpenDatabase
	Save(db *gokeepasslib.Database, dbPath, keyfilePath, password string) error // Enhanced save with re-locking

	// Group CRUD operations
	FindGroupsByName(db *gokeepasslib.Database, groupName string) ([]*gokeepasslib.Group, error)
	FindGroupsByNameInParent(parentGroup *gokeepasslib.Group, groupName string) ([]*gokeepasslib.Group, error)
	CreateGroup(parentGroup *gokeepasslib.Group, groupName string) *gokeepasslib.Group
	CloneGroup(sourceGroup *gokeepasslib.Group, newName string) (*gokeepasslib.Group, error) // Clone group recursively
	DeleteGroup(parentGroup *gokeepasslib.Group, groupName string) error                     // Delete group by name from parent

	// Entry CRUD operations
	CreateEntry(parentGroup *gokeepasslib.Group, entryTitle string) *gokeepasslib.Entry
	SetEntryField(entry *gokeepasslib.Entry, fieldName, fieldValue string)
	FindEntriesByTitle(group *gokeepasslib.Group, entryTitle string) []*gokeepasslib.Entry
	CreateGroupChain(parentGroup *gokeepasslib.Group, pathSegments []string) *gokeepasslib.Group

	// Attachment operations
	AddAttachment(db *gokeepasslib.Database, entry *gokeepasslib.Entry, filename string, content []byte) error
	HasAttachment(entry *gokeepasslib.Entry, filename string) bool
	ListAttachments(entry *gokeepasslib.Entry) []string
}

// KeePassManager implements DatabaseManager
type KeePassManager struct{}

// NewDatabaseManager creates a new database manager
// Following DIP - factory function
func NewDatabaseManager() DatabaseManager {
	return &KeePassManager{}
}

// Create creates a new KeePass database with keyfile protection
func (m *KeePassManager) Create(dbPath, keyfilePath, password string) error {
	// Validate password is not empty
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	// Generate military-grade keyfile first
	if err := m.GenerateKeyfile(keyfilePath); err != nil {
		return fmt.Errorf("failed to generate keyfile: %w", err)
	}

	// Create database with KDBX 4 format for better binary handling
	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion4())
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		return fmt.Errorf("failed to create credentials: %w", err)
	}
	db.Credentials = credentials

	// Create the root group "SECRETS YOHNAH"
	// The first group in Groups slice becomes the root group
	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "SECRETS YOHNAH"
	db.Content.Root.Groups = []gokeepasslib.Group{rootGroup}

	// Lock the database to prepare for writing
	if err := db.LockProtectedEntries(); err != nil {
		return fmt.Errorf("failed to lock database: %w", err)
	}

	// Write database to file
	file, err := os.Create(dbPath)
	if err != nil {
		return fmt.Errorf("failed to create database file: %w", err)
	}
	defer file.Close()

	// Set secure permissions
	if err := os.Chmod(dbPath, 0600); err != nil {
		return fmt.Errorf("failed to set database permissions: %w", err)
	}

	// Encode and write
	keepassEncoder := gokeepasslib.NewEncoder(file)
	if err := keepassEncoder.Encode(db); err != nil {
		return fmt.Errorf("failed to encode database: %w", err)
	}

	return nil
}

// Exists checks if a database file exists
func (m *KeePassManager) Exists(dbPath string) bool {
	_, err := os.Stat(dbPath)
	return err == nil
}

// GenerateKeyfile generates a military-grade keyfile with 64 bytes of random data
func (m *KeePassManager) GenerateKeyfile(keyfilePath string) error {
	// Generate 64 bytes of cryptographically secure random data (military-grade)
	keyfileData := make([]byte, 64)
	if _, err := rand.Read(keyfileData); err != nil {
		return fmt.Errorf("failed to generate random data: %w", err)
	}

	// Write keyfile with secure permissions (0600)
	if err := os.WriteFile(keyfilePath, keyfileData, 0600); err != nil {
		return fmt.Errorf("failed to write keyfile: %w", err)
	}

	return nil
}

// OpenDatabase opens an existing KeePass database
// Following SRP - handles database opening logic
func (m *KeePassManager) OpenDatabase(dbPath, keyfilePath, password string) (*gokeepasslib.Database, error) {
	// Validate inputs
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}

	// Create credentials
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create credentials: %w", err)
	}

	// Open database file
	file, err := os.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database file: %w", err)
	}
	defer file.Close()

	// Decode database
	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials
	decoder := gokeepasslib.NewDecoder(file)
	if err := decoder.Decode(db); err != nil {
		return nil, fmt.Errorf("failed to decode database: %w", err)
	}

	// Unlock protected entries
	if err := db.UnlockProtectedEntries(); err != nil {
		return nil, fmt.Errorf("failed to unlock database: %w", err)
	}

	return db, nil
}

// SaveDatabase saves a KeePass database to file
// Following SRP - handles database saving logic
func (m *KeePassManager) SaveDatabase(db *gokeepasslib.Database, dbPath string) error {
	// Lock protected entries before saving
	if err := db.LockProtectedEntries(); err != nil {
		return fmt.Errorf("failed to lock database: %w", err)
	}

	// Open file for writing
	file, err := os.Create(dbPath)
	if err != nil {
		return fmt.Errorf("failed to create database file: %w", err)
	}
	defer file.Close()

	// Set secure permissions
	if err := os.Chmod(dbPath, 0600); err != nil {
		return fmt.Errorf("failed to set database permissions: %w", err)
	}

	// Encode and write
	encoder := gokeepasslib.NewEncoder(file)
	if err := encoder.Encode(db); err != nil {
		return fmt.Errorf("failed to encode database: %w", err)
	}

	return nil
}

// FindGroupsByName searches for groups with a specific name in the SECRETS YOHNAH group
// Following SRP - handles group searching logic
func (m *KeePassManager) FindGroupsByName(db *gokeepasslib.Database, groupName string) ([]*gokeepasslib.Group, error) {
	var foundGroups []*gokeepasslib.Group

	// Get the SECRETS YOHNAH root group
	if len(db.Content.Root.Groups) == 0 {
		return foundGroups, fmt.Errorf("database has no root groups")
	}
	secretsYonahGroup := &db.Content.Root.Groups[0] // Should be "SECRETS YOHNAH"

	// Search within SECRETS YOHNAH group (profiles are children of SECRETS YOHNAH)
	for i := range secretsYonahGroup.Groups {
		if secretsYonahGroup.Groups[i].Name == groupName {
			foundGroups = append(foundGroups, &secretsYonahGroup.Groups[i])
		}
	}

	return foundGroups, nil
}

// FindGroupsByNameInParent searches for groups with a specific name within a parent group
// Following SRP - handles group searching within parent logic
func (m *KeePassManager) FindGroupsByNameInParent(parentGroup *gokeepasslib.Group, groupName string) ([]*gokeepasslib.Group, error) {
	var foundGroups []*gokeepasslib.Group

	// Search within the specified parent group
	for i := range parentGroup.Groups {
		if parentGroup.Groups[i].Name == groupName {
			foundGroups = append(foundGroups, &parentGroup.Groups[i])
		}
	}

	return foundGroups, nil
}

// CreateGroup creates a new group under the specified parent group
// Following SRP - handles group creation logic
func (m *KeePassManager) CreateGroup(parentGroup *gokeepasslib.Group, groupName string) *gokeepasslib.Group {
	newGroup := gokeepasslib.NewGroup()
	newGroup.Name = groupName
	parentGroup.Groups = append(parentGroup.Groups, newGroup)
	return &parentGroup.Groups[len(parentGroup.Groups)-1]
}

// CreateEntry creates a new entry under the specified parent group
// Following SRP - handles entry creation logic
func (m *KeePassManager) CreateEntry(parentGroup *gokeepasslib.Group, entryTitle string) *gokeepasslib.Entry {
	newEntry := gokeepasslib.NewEntry()
	newEntry.Values = append(newEntry.Values, gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: entryTitle}})
	parentGroup.Entries = append(parentGroup.Entries, newEntry)
	return &parentGroup.Entries[len(parentGroup.Entries)-1]
}

// SetEntryField sets a field value in an entry (creates or updates)
// Following SRP - handles entry field manipulation logic
func (m *KeePassManager) SetEntryField(entry *gokeepasslib.Entry, fieldName, fieldValue string) {
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

// FindEntriesByTitle searches for entries with a specific title within a group
// Following SRP - handles entry searching logic
func (m *KeePassManager) FindEntriesByTitle(group *gokeepasslib.Group, entryTitle string) []*gokeepasslib.Entry {
	var foundEntries []*gokeepasslib.Entry

	for i := range group.Entries {
		for _, value := range group.Entries[i].Values {
			if value.Key == "Title" && value.Value.Content == entryTitle {
				foundEntries = append(foundEntries, &group.Entries[i])
				break
			}
		}
	}

	return foundEntries
}

// CreateGroupChain creates a chain of nested groups following a path
// Following SRP - handles creation of nested group structures
func (m *KeePassManager) CreateGroupChain(parentGroup *gokeepasslib.Group, pathSegments []string) *gokeepasslib.Group {
	currentGroup := parentGroup

	for _, segment := range pathSegments {
		// Check if group already exists
		found := false
		for i := range currentGroup.Groups {
			if currentGroup.Groups[i].Name == segment {
				currentGroup = &currentGroup.Groups[i]
				found = true
				break
			}
		}

		// Create group if it doesn't exist
		if !found {
			currentGroup = m.CreateGroup(currentGroup, segment)
		}
	}

	return currentGroup
}

// AddAttachment adds a file attachment to the specified entry
// Returns error if attachment with same filename already exists
func (m *KeePassManager) AddAttachment(db *gokeepasslib.Database, entry *gokeepasslib.Entry, filename string, content []byte) error {
	// Validate inputs
	if db == nil {
		return fmt.Errorf("database cannot be nil")
	}
	if entry == nil {
		return fmt.Errorf("entry cannot be nil")
	}
	if filename == "" {
		return fmt.Errorf("filename cannot be empty")
	}

	// Check if attachment already exists
	for _, binRef := range entry.Binaries {
		if binRef.Name == filename {
			return fmt.Errorf("attachment '%s' already exists in entry", filename)
		}
	}

	// Add binary content to database
	// In KDBX 4, binaries are stored in InnerHeader
	// In KDBX 3.1, binaries are stored in Metadata
	// db.AddBinary handles both cases automatically
	binary := db.AddBinary(content)
	if binary == nil {
		return fmt.Errorf("failed to add binary content to database")
	}

	// Create binary reference and add to entry
	binaryRef := binary.CreateReference(filename)
	entry.Binaries = append(entry.Binaries, binaryRef)

	return nil
}

// HasAttachment checks if the specified entry has an attachment with the given filename
func (m *KeePassManager) HasAttachment(entry *gokeepasslib.Entry, filename string) bool {
	if entry == nil || filename == "" {
		return false
	}

	for _, binRef := range entry.Binaries {
		if binRef.Name == filename {
			return true
		}
	}
	return false
}

// ListAttachments returns a slice of attachment filenames for the specified entry
func (m *KeePassManager) ListAttachments(entry *gokeepasslib.Entry) []string {
	if entry == nil {
		return []string{}
	}

	attachments := make([]string, 0, len(entry.Binaries))
	for _, binRef := range entry.Binaries {
		attachments = append(attachments, binRef.Name)
	}
	return attachments
}

// Open is an alias for OpenDatabase for consistency (October 4, 2025)
func (m *KeePassManager) Open(dbPath, keyfilePath, password string) (*gokeepasslib.Database, error) {
	return m.OpenDatabase(dbPath, keyfilePath, password)
}

// Save saves the database with proper locking and credentials (October 4, 2025)
func (m *KeePassManager) Save(db *gokeepasslib.Database, dbPath, keyfilePath, password string) error {
	// Set credentials
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		return fmt.Errorf("failed to create credentials: %w", err)
	}
	db.Credentials = credentials

	// Lock protected entries before saving
	if err := db.LockProtectedEntries(); err != nil {
		return fmt.Errorf("failed to lock database: %w", err)
	}

	// Save database
	return m.SaveDatabase(db, dbPath)
}

// CloneGroup creates a deep copy of a group with all its contents (October 4, 2025)
// Following SRP - Single Responsibility: handles group cloning with new UUIDs
func (m *KeePassManager) CloneGroup(sourceGroup *gokeepasslib.Group, newName string) (*gokeepasslib.Group, error) {
	if sourceGroup == nil {
		return nil, fmt.Errorf("source group cannot be nil")
	}

	// Create new group with new name
	clonedGroup := gokeepasslib.NewGroup()
	clonedGroup.Name = newName

	// Clone all entries in the group
	clonedGroup.Entries = make([]gokeepasslib.Entry, len(sourceGroup.Entries))
	for i, entry := range sourceGroup.Entries {
		// Create new entry with new UUID
		clonedEntry := gokeepasslib.NewEntry()

		// Copy all values (Title, Password, UserName, URL, Notes, custom fields)
		clonedEntry.Values = make([]gokeepasslib.ValueData, len(entry.Values))
		for j, value := range entry.Values {
			clonedEntry.Values[j] = gokeepasslib.ValueData{
				Key:   value.Key,
				Value: gokeepasslib.V{Content: value.Value.Content},
			}
		}

		// Copy binaries (attachments)
		clonedEntry.Binaries = make([]gokeepasslib.BinaryReference, len(entry.Binaries))
		for j, binRef := range entry.Binaries {
			clonedEntry.Binaries[j] = gokeepasslib.BinaryReference{
				Name:  binRef.Name,
				Value: binRef.Value,
			}
		}

		// Copy times
		clonedEntry.Times = entry.Times

		clonedGroup.Entries[i] = clonedEntry
	}

	// Recursively clone all subgroups
	clonedGroup.Groups = make([]gokeepasslib.Group, len(sourceGroup.Groups))
	for i, subGroup := range sourceGroup.Groups {
		clonedSubGroup, err := m.CloneGroup(&subGroup, subGroup.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to clone subgroup '%s': %w", subGroup.Name, err)
		}
		clonedGroup.Groups[i] = *clonedSubGroup
	}

	// Copy times
	clonedGroup.Times = sourceGroup.Times

	return &clonedGroup, nil
}

// DeleteGroup deletes a group by name from a parent group
// Following SRP - Single Responsibility: handles group deletion
// Returns error if group not found
func (m *KeePassManager) DeleteGroup(parentGroup *gokeepasslib.Group, groupName string) error {
	// Find the index of the group to delete
	groupIndex := -1
	for i := range parentGroup.Groups {
		if parentGroup.Groups[i].Name == groupName {
			groupIndex = i
			break
		}
	}

	// If not found, return error
	if groupIndex == -1 {
		return fmt.Errorf("group '%s' not found in parent group", groupName)
	}

	// Delete the group by removing it from the slice
	parentGroup.Groups = append(parentGroup.Groups[:groupIndex], parentGroup.Groups[groupIndex+1:]...)

	return nil
}
