package keepass

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"
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
	CreateEntry(dbPath, keyfilePath, password, profileName, envName, entryPath string) error
	EntryExists(dbPath, keyfilePath, password, profileName, envName, entryPath string) (bool, error)
	GetEntriesByEnvironment(dbPath, keyfilePath, password, profileName, envName string) ([]string, error)
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

// CreateEntry creates a new entry in the database under a specific environment
// Creates intermediate groups automatically if they don't exist
// Entry is created empty (no custom fields)
func (m *manager) CreateEntry(dbPath, keyfilePath, password, profileName, envName, entryPath string) error {
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

	// Find HEAD group within profile
	var headGroup *gokeepasslib.Group
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == "HEAD" {
			headGroup = &profileGroup.Groups[i]
			break
		}
	}

	if headGroup == nil {
		return fmt.Errorf("HEAD group not found in profile '%s'", profileName)
	}

	// Find environment group within HEAD
	var envGroup *gokeepasslib.Group
	for i := range headGroup.Groups {
		if headGroup.Groups[i].Name == envName {
			envGroup = &headGroup.Groups[i]
			break
		}
	}

	if envGroup == nil {
		return fmt.Errorf("environment '%s' not found in profile '%s'", envName, profileName)
	}

	// Parse entry path
	// Remove leading slash
	if len(entryPath) > 0 && entryPath[0] == '/' {
		entryPath = entryPath[1:]
	}

	// Remove environment prefix from path if present (case-insensitive)
	envPrefix := envName + "/"
	if len(entryPath) >= len(envPrefix) {
		if strings.EqualFold(entryPath[:len(envPrefix)], envPrefix) {
			entryPath = entryPath[len(envPrefix):]
		}
	}

	// Split path into components
	if entryPath == "" {
		return fmt.Errorf("entry path is empty after parsing")
	}

	components := strings.Split(entryPath, "/")
	if len(components) == 0 {
		return fmt.Errorf("invalid entry path")
	}

	// Navigate/create intermediate groups
	currentGroup := envGroup
	for i := 0; i < len(components)-1; i++ {
		groupName := components[i]
		if groupName == "" {
			continue
		}

		// Find or create group
		found := false
		for j := range currentGroup.Groups {
			if currentGroup.Groups[j].Name == groupName {
				currentGroup = &currentGroup.Groups[j]
				found = true
				break
			}
		}

		if !found {
			// Create intermediate group
			newGroup := gokeepasslib.NewGroup()
			newGroup.Name = groupName
			currentGroup.Groups = append(currentGroup.Groups, newGroup)
			currentGroup = &currentGroup.Groups[len(currentGroup.Groups)-1]
		}
	}

	// Create entry in the final group
	entryName := components[len(components)-1]
	if entryName == "" {
		return fmt.Errorf("entry name is empty")
	}

	// Create new empty entry
	newEntry := gokeepasslib.NewEntry()
	newEntry.Values = append(newEntry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: entryName},
	})

	// Add entry to current group
	currentGroup.Entries = append(currentGroup.Entries, newEntry)

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

// EntryExists checks if an entry exists at the specified path within an environment
func (m *manager) EntryExists(dbPath, keyfilePath, password, profileName, envName, entryPath string) (bool, error) {
	// Open database
	db, err := m.OpenDatabase(dbPath, keyfilePath, password)
	if err != nil {
		return false, fmt.Errorf("failed to open database: %w", err)
	}

	// Check if root group exists
	if len(db.Content.Root.Groups) == 0 {
		return false, nil
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
		return false, nil
	}

	// Find HEAD group within profile
	var headGroup *gokeepasslib.Group
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == "HEAD" {
			headGroup = &profileGroup.Groups[i]
			break
		}
	}

	if headGroup == nil {
		return false, nil
	}

	// Find environment group within HEAD
	var envGroup *gokeepasslib.Group
	for i := range headGroup.Groups {
		if headGroup.Groups[i].Name == envName {
			envGroup = &headGroup.Groups[i]
			break
		}
	}

	if envGroup == nil {
		return false, nil
	}

	// Parse entry path - remove leading slash if present
	if len(entryPath) > 0 && entryPath[0] == '/' {
		entryPath = entryPath[1:]
	}

	// Remove environment prefix from path if present (case-insensitive)
	envPrefix := envName + "/"
	if len(entryPath) >= len(envPrefix) {
		if strings.EqualFold(entryPath[:len(envPrefix)], envPrefix) {
			entryPath = entryPath[len(envPrefix):]
		}
	}

	// Split path into components
	if entryPath == "" {
		return false, nil
	}

	components := strings.Split(entryPath, "/")
	if len(components) == 0 {
		return false, nil
	}

	// Navigate through intermediate groups
	currentGroup := envGroup
	for i := 0; i < len(components)-1; i++ {
		groupName := components[i]
		if groupName == "" {
			continue
		}

		// Find group
		found := false
		for j := range currentGroup.Groups {
			if currentGroup.Groups[j].Name == groupName {
				currentGroup = &currentGroup.Groups[j]
				found = true
				break
			}
		}

		if !found {
			// Group doesn't exist, so entry doesn't exist
			return false, nil
		}
	}

	// Check if entry exists in the final group
	entryName := components[len(components)-1]
	if entryName == "" {
		return false, nil
	}

	// Search for entry by Title
	for _, entry := range currentGroup.Entries {
		for _, value := range entry.Values {
			if value.Key == "Title" && value.Value.Content == entryName {
				return true, nil
			}
		}
	}

	return false, nil
}

// GetEntriesByEnvironment retrieves all entry paths within a specific environment
// Returns paths relative to the environment (without environment prefix)
func (m *manager) GetEntriesByEnvironment(dbPath, keyfilePath, password, profileName, envName string) ([]string, error) {
	// Open database
	db, err := m.OpenDatabase(dbPath, keyfilePath, password)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Check if root group exists
	if len(db.Content.Root.Groups) == 0 {
		return []string{}, nil
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
		return []string{}, nil
	}

	// Find HEAD group within profile
	var headGroup *gokeepasslib.Group
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == "HEAD" {
			headGroup = &profileGroup.Groups[i]
			break
		}
	}

	if headGroup == nil {
		return []string{}, nil
	}

	// Find environment group within HEAD
	var envGroup *gokeepasslib.Group
	for i := range headGroup.Groups {
		if headGroup.Groups[i].Name == envName {
			envGroup = &headGroup.Groups[i]
			break
		}
	}

	if envGroup == nil {
		return []string{}, nil
	}

	// Recursively collect all entry paths
	var entries []string
	collectEntries(envGroup, "", &entries)

	return entries, nil
}

// collectEntries recursively collects all entry paths in a group
func collectEntries(group *gokeepasslib.Group, currentPath string, entries *[]string) {
	// Collect entries in current group
	for _, entry := range group.Entries {
		// Get entry title
		var title string
		for _, value := range entry.Values {
			if value.Key == "Title" {
				title = value.Value.Content
				break
			}
		}

		if title != "" {
			var entryPath string
			if currentPath == "" {
				entryPath = title
			} else {
				entryPath = currentPath + "/" + title
			}
			*entries = append(*entries, entryPath)
		}
	}

	// Recursively process subgroups
	for i := range group.Groups {
		subGroupName := group.Groups[i].Name
		var newPath string
		if currentPath == "" {
			newPath = subGroupName
		} else {
			newPath = currentPath + "/" + subGroupName
		}
		collectEntries(&group.Groups[i], newPath, entries)
	}
}
