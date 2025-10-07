package keepass

import (
	"crypto/rand"
	"fmt"
	"os"
	"time"

	"github.com/tobischo/gokeepasslib/v3"
)

// Manager interface defines operations for KeePass database management
type Manager interface {
	CreateDatabase(dbPath, keyfilePath, password, rootGroupName string) error
	OpenDatabase(dbPath, keyfilePath, password string) (*gokeepasslib.Database, error)
	GenerateKeyfile(keyfilePath string) error
	CreateProfile(dbPath, keyfilePath, password, profileName string) error
	ProfileExists(dbPath, keyfilePath, password, profileName string) (bool, error)
	CreateGroup(dbPath, keyfilePath, password, profileName, parentGroupName, groupName string) error
}

// manager implements the Manager interface
type manager struct{}

// NewManager creates a new KeePass manager instance
func NewManager() Manager {
	return &manager{}
}

// GenerateKeyfile generates a cryptographically secure keyfile
// Uses 64 bytes (512 bits) for military-grade security
func (m *manager) GenerateKeyfile(keyfilePath string) error {
	// Generate 64 random bytes using crypto/rand (CSPRNG)
	keyData := make([]byte, 64)
	_, err := rand.Read(keyData)
	if err != nil {
		return fmt.Errorf("failed to generate random key data: %w", err)
	}

	// Write keyfile to disk
	err = os.WriteFile(keyfilePath, keyData, 0600)
	if err != nil {
		return fmt.Errorf("failed to write keyfile: %w", err)
	}

	return nil
}

// CreateDatabase creates a new KeePass database in KDBX4 format
// Protected with both password and keyfile
func (m *manager) CreateDatabase(dbPath, keyfilePath, password, rootGroupName string) error {
	// Create new database in KDBX4 format
	db := gokeepasslib.NewDatabase(
		gokeepasslib.WithDatabaseKDBXVersion4(),
	)

	// Create credentials with password and keyfile
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		return fmt.Errorf("failed to create credentials: %w", err)
	}

	// Assign credentials to database
	db.Credentials = credentials

	// Create root group with custom name if provided
	if rootGroupName != "" {
		rootGroup := gokeepasslib.NewGroup()
		rootGroup.Name = rootGroupName
		db.Content.Root.Groups = []gokeepasslib.Group{rootGroup}
	}

	// Lock protected entries (encrypt sensitive data)
	err = db.LockProtectedEntries()
	if err != nil {
		return fmt.Errorf("failed to lock protected entries: %w", err)
	}

	// Save database to file
	file, err := os.Create(dbPath)
	if err != nil {
		return fmt.Errorf("failed to create database file: %w", err)
	}
	defer file.Close()

	// Create encoder and encode database
	encoder := gokeepasslib.NewEncoder(file)
	err = encoder.Encode(db)
	if err != nil {
		return fmt.Errorf("failed to encode database: %w", err)
	}

	return nil
}

// OpenDatabase opens an existing KeePass database
// Returns unlocked database or error if credentials are invalid
func (m *manager) OpenDatabase(dbPath, keyfilePath, password string) (*gokeepasslib.Database, error) {
	// Create credentials FIRST - needed for decoding encrypted database
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create credentials: %w", err)
	}

	// Read database file
	file, err := os.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database file: %w", err)
	}
	defer file.Close()

	// Create database and assign credentials BEFORE decoding
	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials

	// Decode database (will use credentials to decrypt)
	decoder := gokeepasslib.NewDecoder(file)
	err = decoder.Decode(db)
	if err != nil {
		return nil, fmt.Errorf("failed to decode database: %w", err)
	}

	// Unlock protected entries (decrypt sensitive fields)
	err = db.UnlockProtectedEntries()
	if err != nil {
		return nil, fmt.Errorf("failed to unlock database (wrong password or keyfile): %w", err)
	}

	return db, nil
}

// ProfileExists checks if a profile group exists in the database
func (m *manager) ProfileExists(dbPath, keyfilePath, password, profileName string) (bool, error) {
	// Open database
	db, err := m.OpenDatabase(dbPath, keyfilePath, password)
	if err != nil {
		return false, fmt.Errorf("failed to open database: %w", err)
	}

	// Check if root group has any groups
	if len(db.Content.Root.Groups) == 0 {
		return false, nil
	}

	// Search for profile in root's children
	rootGroup := &db.Content.Root.Groups[0]
	for _, group := range rootGroup.Groups {
		if group.Name == profileName {
			return true, nil
		}
	}

	return false, nil
}

// CreateProfile creates a new profile structure in the database:
// Profile (group) → HEAD (group) → metadata (entry)
func (m *manager) CreateProfile(dbPath, keyfilePath, password, profileName string) error {
	// Open database
	db, err := m.OpenDatabase(dbPath, keyfilePath, password)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Check if root group exists
	if len(db.Content.Root.Groups) == 0 {
		return fmt.Errorf("database has no root group")
	}

	rootGroup := &db.Content.Root.Groups[0]

	// Check if profile already exists (idempotent operation)
	for _, group := range rootGroup.Groups {
		if group.Name == profileName {
			// Profile already exists, skip creation (idempotent)
			return nil
		}
	}

	// Create profile group
	profileGroup := gokeepasslib.NewGroup()
	profileGroup.Name = profileName

	// Create HEAD group
	headGroup := gokeepasslib.NewGroup()
	headGroup.Name = "HEAD"

	// Create metadata entry
	metadataEntry := gokeepasslib.NewEntry()
	metadataEntry.Values = append(metadataEntry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: "metadata"},
	})

	// Add custom fields for version and datetime
	metadataEntry.Values = append(metadataEntry.Values, gokeepasslib.ValueData{
		Key:   "version",
		Value: gokeepasslib.V{Content: "1"},
	})

	// Get current datetime in ISO 8601 format
	datetime := time.Now().Format(time.RFC3339)
	metadataEntry.Values = append(metadataEntry.Values, gokeepasslib.ValueData{
		Key:   "datetime",
		Value: gokeepasslib.V{Content: datetime},
	})

	// Add metadata entry to HEAD group
	headGroup.Entries = append(headGroup.Entries, metadataEntry)

	// Add HEAD group to profile group
	profileGroup.Groups = append(profileGroup.Groups, headGroup)

	// Add profile group to root group
	rootGroup.Groups = append(rootGroup.Groups, profileGroup)

	// Lock protected entries before saving
	if err := db.LockProtectedEntries(); err != nil {
		return fmt.Errorf("failed to lock protected entries: %w", err)
	}

	// Save database
	file, err := os.Create(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database file for writing: %w", err)
	}
	defer file.Close()

	encoder := gokeepasslib.NewEncoder(file)
	if err := encoder.Encode(db); err != nil {
		return fmt.Errorf("failed to save database: %w", err)
	}

	return nil
}

// CreateGroup creates a new group under a parent group within a profile
// Path: Profile > ParentGroup > NewGroup
// Idempotent: if group already exists, returns nil without error
func (m *manager) CreateGroup(dbPath, keyfilePath, password, profileName, parentGroupName, groupName string) error {
	// Open database
	db, err := m.OpenDatabase(dbPath, keyfilePath, password)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Check if root group exists
	if len(db.Content.Root.Groups) == 0 {
		return fmt.Errorf("database has no root group")
	}

	rootGroup := &db.Content.Root.Groups[0]

	// Find profile group
	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profileName {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}

	if profileGroup == nil {
		return fmt.Errorf("profile '%s' not found", profileName)
	}

	// Find parent group within profile
	var parentGroup *gokeepasslib.Group
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == parentGroupName {
			parentGroup = &profileGroup.Groups[i]
			break
		}
	}

	if parentGroup == nil {
		return fmt.Errorf("parent group '%s' not found in profile '%s'", parentGroupName, profileName)
	}

	// Check if group already exists (idempotent operation)
	for _, group := range parentGroup.Groups {
		if group.Name == groupName {
			// Group already exists, skip creation (idempotent)
			return nil
		}
	}

	// Create new group
	newGroup := gokeepasslib.NewGroup()
	newGroup.Name = groupName

	// Add group to parent
	parentGroup.Groups = append(parentGroup.Groups, newGroup)

	// Lock protected entries before saving
	if err := db.LockProtectedEntries(); err != nil {
		return fmt.Errorf("failed to lock protected entries: %w", err)
	}

	// Save database
	file, err := os.Create(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database file for writing: %w", err)
	}
	defer file.Close()

	encoder := gokeepasslib.NewEncoder(file)
	if err := encoder.Encode(db); err != nil {
		return fmt.Errorf("failed to save database: %w", err)
	}

	return nil
}
