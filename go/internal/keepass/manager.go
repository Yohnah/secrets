package keepass

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tobischo/gokeepasslib/v3"
)

// Manager interface defines operations for KeePass database management
type Manager interface {
	// Session management
	Open(dbPath, keyfilePath, password string) error
	SaveAndClose() error
	CloseWithoutSave() error
	IsOpen() bool
	GetDatabase() *gokeepasslib.Database

	// Database operations (require open session)
	CreateDatabase(dbPath, keyfilePath, password, rootGroupName string) error
	GenerateKeyfile(keyfilePath string) error
	CreateProfile(profileName string) error
	ProfileExists(profileName string) (bool, error)
	CreateGroup(profileName, parentGroupName, groupName string) (bool, error)
	GroupExists(profileName, parentGroupName, groupName string) (bool, error)
	CreateEntry(profileName, envName, entryPath string) error
	EntryExists(profileName, envName, entryPath string) (bool, error)
	GetEntriesByEnvironment(profileName, envName string) ([]string, error)
	GetRootGroups() ([]string, error)
	GetGroupsByParent(parentPath string) ([]string, error)
	GetEntriesByGroup(groupPath string) ([]string, error)
	GetFieldsByEntry(entryPath string) ([]string, error)

	// Field operations (require open session)
	IsStandardField(fieldName string) bool
	SetStandardField(profileName, envName, entryPath, fieldName, value string) error
	SetCustomField(profileName, envName, entryPath, fieldName, value string) error
	CreateAttachment(profileName, envName, entryPath, attachmentName string, data []byte) error
	FieldExists(profileName, envName, entryPath, fieldName string) (bool, error)

	// Snapshots operations (require open session)
	ListProfileTreeGroups(profileName string) ([]string, error)
	GetTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName string) (string, error)
	CloneTreeGroup(profileName, sourceTreeGroup, targetTreeGroup string) error
	SetTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName, value string) error
	TreeGroupExists(profileName, treeGroup string) (bool, error)
	RenameTreeGroup(profileName, oldName, newName string) error
	DeleteTreeGroup(profileName, treeGroup string) error
}

// manager implements the Manager interface
type manager struct {
	db          *gokeepasslib.Database
	dbPath      string
	keyfilePath string
	password    string
}

// NewManager creates a new instance of the KeePass Manager
func NewManager() Manager {
	return &manager{
		db: nil,
	}
}

// Open opens a KeePass database and keeps it in memory
// Must be called before any database operations
func (m *manager) Open(dbPath, keyfilePath, password string) error {
	if m.db != nil {
		return fmt.Errorf("database already open")
	}

	// Validate input
	if dbPath == "" {
		return fmt.Errorf("database path cannot be empty")
	}
	if keyfilePath == "" {
		return fmt.Errorf("keyfile path cannot be empty")
	}
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	// Sanitize paths
	sanitizedDBPath, err := sanitizePath(dbPath)
	if err != nil {
		return fmt.Errorf("invalid database path: %w", err)
	}
	sanitizedKeyfilePath, err := sanitizePath(keyfilePath)
	if err != nil {
		return fmt.Errorf("invalid keyfile path: %w", err)
	}

	// Open database file
	file, err := os.Open(sanitizedDBPath)
	if err != nil {
		return fmt.Errorf("failed to open database file: %w", err)
	}
	defer file.Close()

	// Create credentials
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, sanitizedKeyfilePath)
	if err != nil {
		return fmt.Errorf("failed to create credentials: %w", err)
	}

	// Decode database
	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials
	err = gokeepasslib.NewDecoder(file).Decode(db)
	if err != nil {
		return fmt.Errorf("failed to decode database: %w", err)
	}

	// Unlock database
	err = db.UnlockProtectedEntries()
	if err != nil {
		return fmt.Errorf("failed to unlock database: %w", err)
	}

	// Store session
	m.db = db
	m.dbPath = sanitizedDBPath
	m.keyfilePath = sanitizedKeyfilePath
	m.password = password

	return nil
}

// SaveAndClose saves changes and closes the database session
func (m *manager) SaveAndClose() error {
	if m.db == nil {
		return fmt.Errorf("no database open")
	}

	// Lock protected entries
	err := m.db.LockProtectedEntries()
	if err != nil {
		// Clear session even on error
		m.db = nil
		m.dbPath = ""
		m.keyfilePath = ""
		m.password = ""
		return fmt.Errorf("failed to lock database: %w", err)
	}

	// Open file for writing
	file, err := os.Create(m.dbPath)
	if err != nil {
		// Clear session even on error
		m.db = nil
		m.dbPath = ""
		m.keyfilePath = ""
		m.password = ""
		return fmt.Errorf("failed to open database file for writing: %w", err)
	}
	defer file.Close()

	// Encode and save
	keepassEncoder := gokeepasslib.NewEncoder(file)
	err = keepassEncoder.Encode(m.db)
	if err != nil {
		// Clear session even on error
		m.db = nil
		m.dbPath = ""
		m.keyfilePath = ""
		m.password = ""
		return fmt.Errorf("failed to encode database: %w", err)
	}

	// Clear session
	m.db = nil
	m.dbPath = ""
	m.keyfilePath = ""
	m.password = ""

	return nil
}

// CloseWithoutSave closes the database session without saving changes
func (m *manager) CloseWithoutSave() error {
	if m.db == nil {
		return fmt.Errorf("no database open")
	}

	// Clear session without saving
	m.db = nil
	m.dbPath = ""
	m.keyfilePath = ""
	m.password = ""

	return nil
}

// IsOpen returns true if a database session is currently open
func (m *manager) IsOpen() bool {
	return m.db != nil
}

// GetDatabase returns the currently open database
// Returns nil if no database is open
func (m *manager) GetDatabase() *gokeepasslib.Database {
	return m.db
}

// sanitizePath cleans and validates a file path to prevent path traversal attacks
func sanitizePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path cannot be empty")
	}

	// Check for path traversal attempts BEFORE cleaning
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("path contains invalid '..' components")
	}

	// Clean the path to resolve any . or .. components
	cleanPath := filepath.Clean(path)

	// Additional check: ensure the path doesn't start with .. after cleaning
	if strings.HasPrefix(cleanPath, "..") {
		return "", fmt.Errorf("path traversal detected")
	}

	return cleanPath, nil
}

// GenerateKeyfile generates a cryptographically secure keyfile
// Uses 64 bytes (512 bits) for military-grade security
func (m *manager) GenerateKeyfile(keyfilePath string) error {
	// Validate input parameters
	if keyfilePath == "" {
		return fmt.Errorf("keyfile path cannot be empty")
	}

	// Sanitize path to prevent traversal attacks
	sanitizedPath, err := sanitizePath(keyfilePath)
	if err != nil {
		return fmt.Errorf("invalid keyfile path: %w", err)
	}

	// Generate 64 random bytes using crypto/rand (CSPRNG)
	keyData := make([]byte, 64)
	_, err = rand.Read(keyData)
	if err != nil {
		return fmt.Errorf("failed to generate random key data: %w", err)
	}

	// Write keyfile to disk
	err = os.WriteFile(sanitizedPath, keyData, 0600)
	if err != nil {
		return fmt.Errorf("failed to write keyfile: %w", err)
	}

	return nil
}

// CreateDatabase creates a new KeePass database in KDBX4 format
// Protected with both password and keyfile
func (m *manager) CreateDatabase(dbPath, keyfilePath, password, rootGroupName string) error {
	// Validate input parameters
	if dbPath == "" {
		return fmt.Errorf("database path cannot be empty")
	}
	if keyfilePath == "" {
		return fmt.Errorf("keyfile path cannot be empty")
	}
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}
	if rootGroupName == "" {
		return fmt.Errorf("root group name cannot be empty")
	}

	// Sanitize paths to prevent traversal attacks
	sanitizedDbPath, err := sanitizePath(dbPath)
	if err != nil {
		return fmt.Errorf("invalid database path: %w", err)
	}
	sanitizedKeyfilePath, err := sanitizePath(keyfilePath)
	if err != nil {
		return fmt.Errorf("invalid keyfile path: %w", err)
	}

	// Create new database in KDBX4 format
	db := gokeepasslib.NewDatabase(
		gokeepasslib.WithDatabaseKDBXVersion4(),
	)

	// Create credentials with password and keyfile
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, sanitizedKeyfilePath)
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

	// Save database to file with restrictive permissions (0600)
	file, err := os.OpenFile(sanitizedDbPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
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
	// Validate input parameters
	if dbPath == "" {
		return nil, fmt.Errorf("database path cannot be empty")
	}
	if keyfilePath == "" {
		return nil, fmt.Errorf("keyfile path cannot be empty")
	}
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}

	// Sanitize paths to prevent traversal attacks
	sanitizedDbPath, err := sanitizePath(dbPath)
	if err != nil {
		return nil, fmt.Errorf("invalid database path: %w", err)
	}
	sanitizedKeyfilePath, err := sanitizePath(keyfilePath)
	if err != nil {
		return nil, fmt.Errorf("invalid keyfile path: %w", err)
	}

	// Create credentials FIRST - needed for decoding encrypted database
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, sanitizedKeyfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create credentials: %w", err)
	}

	// Read database file
	file, err := os.Open(sanitizedDbPath)
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
func (m *manager) ProfileExists(profileName string) (bool, error) {
	// Check session
	if m.db == nil {
		return false, fmt.Errorf("database not open")
	}

	// Validate input parameters
	if profileName == "" {
		return false, fmt.Errorf("profile name cannot be empty")
	}

	// Check if root group has any groups
	if len(m.db.Content.Root.Groups) == 0 {
		return false, nil
	}

	// Search for profile in root's children
	rootGroup := &m.db.Content.Root.Groups[0]
	for _, group := range rootGroup.Groups {
		if group.Name == profileName {
			return true, nil
		}
	}

	return false, nil
}

// GroupExists checks if a group exists under a parent group within a profile
func (m *manager) GroupExists(profileName, parentGroupName, groupName string) (bool, error) {
	// Check session
	if m.db == nil {
		return false, fmt.Errorf("database not open")
	}

	// Validate input parameters
	if profileName == "" {
		return false, fmt.Errorf("profile name cannot be empty")
	}
	if parentGroupName == "" {
		return false, fmt.Errorf("parent group name cannot be empty")
	}
	if groupName == "" {
		return false, fmt.Errorf("group name cannot be empty")
	}

	// Check if root group exists
	if len(m.db.Content.Root.Groups) == 0 {
		return false, nil
	}

	rootGroup := &m.db.Content.Root.Groups[0]

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

	// Find parent group within profile
	var parentGroup *gokeepasslib.Group
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == parentGroupName {
			parentGroup = &profileGroup.Groups[i]
			break
		}
	}

	if parentGroup == nil {
		return false, nil
	}

	// Check if group exists under parent
	for _, group := range parentGroup.Groups {
		if group.Name == groupName {
			return true, nil
		}
	}

	return false, nil
}

// CreateProfile creates a new profile structure in the database:
// Profile (group) → HEAD (group) → metadata (entry)
func (m *manager) CreateProfile(profileName string) error {
	// Check session
	if m.db == nil {
		return fmt.Errorf("database not open")
	}

	// Validate input parameters
	if profileName == "" {
		return fmt.Errorf("profile name cannot be empty")
	}

	// Check if root group exists
	if len(m.db.Content.Root.Groups) == 0 {
		return fmt.Errorf("database has no root group")
	}

	rootGroup := &m.db.Content.Root.Groups[0]

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

	return nil
}

// CreateGroup creates a new group under a parent group within a profile
// Path: Profile > ParentGroup > NewGroup
// Returns (true, nil) if group was created, (false, nil) if already existed
// Idempotent: if group already exists, returns (false, nil) without error
func (m *manager) CreateGroup(profileName, parentGroupName, groupName string) (bool, error) {
	// Check session
	if m.db == nil {
		return false, fmt.Errorf("database not open")
	}

	// Validate input parameters
	if profileName == "" {
		return false, fmt.Errorf("profile name cannot be empty")
	}
	if parentGroupName == "" {
		return false, fmt.Errorf("parent group name cannot be empty")
	}
	if groupName == "" {
		return false, fmt.Errorf("group name cannot be empty")
	}

	// Check if root group exists
	if len(m.db.Content.Root.Groups) == 0 {
		return false, fmt.Errorf("database has no root group")
	}

	rootGroup := &m.db.Content.Root.Groups[0]

	// Find profile group
	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profileName {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}

	if profileGroup == nil {
		return false, fmt.Errorf("profile '%s' not found", profileName)
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
		return false, fmt.Errorf("parent group '%s' not found in profile '%s'", parentGroupName, profileName)
	}

	// Check if group already exists (idempotent operation)
	for _, group := range parentGroup.Groups {
		if group.Name == groupName {
			// Group already exists, skip creation (idempotent)
			return false, nil
		}
	}

	// Create new group
	newGroup := gokeepasslib.NewGroup()
	newGroup.Name = groupName

	// Add group to parent
	parentGroup.Groups = append(parentGroup.Groups, newGroup)

	return true, nil
}

// CreateEntry creates a new entry in the database under a specific environment
// Creates intermediate groups automatically if they don't exist
// Entry is created empty (no custom fields)
func (m *manager) CreateEntry(profileName, envName, entryPath string) error {
	// Check session
	if m.db == nil {
		return fmt.Errorf("database not open")
	}

	// Validate input parameters
	if profileName == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if envName == "" {
		return fmt.Errorf("environment name cannot be empty")
	}
	if entryPath == "" {
		return fmt.Errorf("entry path cannot be empty")
	}

	// Check if root group exists
	if len(m.db.Content.Root.Groups) == 0 {
		return fmt.Errorf("database has no root group")
	}

	rootGroup := &m.db.Content.Root.Groups[0]

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

	return nil
}

// EntryExists checks if an entry exists at the specified path within an environment
func (m *manager) EntryExists(profileName, envName, entryPath string) (bool, error) {
	// Check session
	if m.db == nil {
		return false, fmt.Errorf("database not open")
	}

	// Validate input parameters
	if profileName == "" {
		return false, fmt.Errorf("profile name cannot be empty")
	}
	if envName == "" {
		return false, fmt.Errorf("environment name cannot be empty")
	}
	if entryPath == "" {
		return false, fmt.Errorf("entry path cannot be empty")
	}

	// Check if root group exists
	if len(m.db.Content.Root.Groups) == 0 {
		return false, nil
	}

	rootGroup := &m.db.Content.Root.Groups[0]

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
func (m *manager) GetEntriesByEnvironment(profileName, envName string) ([]string, error) {
	// Check session
	if m.db == nil {
		return nil, fmt.Errorf("database not open")
	}

	// Validate input parameters
	if profileName == "" {
		return nil, fmt.Errorf("profile name cannot be empty")
	}
	if envName == "" {
		return nil, fmt.Errorf("environment name cannot be empty")
	}

	// Check if root group exists
	if len(m.db.Content.Root.Groups) == 0 {
		return []string{}, nil
	}

	rootGroup := &m.db.Content.Root.Groups[0]

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

// GetRootGroups returns the names of all groups directly under the root
func (m *manager) GetRootGroups() ([]string, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database not open")
	}

	if len(m.db.Content.Root.Groups) == 0 {
		return []string{}, nil
	}

	rootGroup := m.db.Content.Root.Groups[0]
	var groups []string
	for _, group := range rootGroup.Groups {
		groups = append(groups, group.Name)
	}

	return groups, nil
}

// GetGroupsByParent returns the names of all groups directly under the specified parent path
func (m *manager) GetGroupsByParent(parentPath string) ([]string, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database not open")
	}

	parentGroup, err := m.findGroupByPath(parentPath)
	if err != nil {
		return nil, err
	}

	var groups []string
	for _, group := range parentGroup.Groups {
		groups = append(groups, group.Name)
	}

	return groups, nil
}

// GetEntriesByGroup returns the names of all entries directly under the specified group path
func (m *manager) GetEntriesByGroup(groupPath string) ([]string, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database not open")
	}

	group, err := m.findGroupByPath(groupPath)
	if err != nil {
		return nil, err
	}

	var entries []string
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
			entries = append(entries, title)
		}
	}

	return entries, nil
}

// GetFieldsByEntry returns all field names (standard and custom) for the specified entry path
func (m *manager) GetFieldsByEntry(entryPath string) ([]string, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database not open")
	}

	entry, err := m.findEntryByPath(entryPath)
	if err != nil {
		return nil, err
	}

	var fields []string
	for _, value := range entry.Values {
		fields = append(fields, value.Key)
	}

	return fields, nil
}

// findGroupByPath finds a group by its full path
func (m *manager) findGroupByPath(path string) (*gokeepasslib.Group, error) {
	if path == "" {
		// Root group
		if len(m.db.Content.Root.Groups) == 0 {
			return nil, fmt.Errorf("root group not found")
		}
		return &m.db.Content.Root.Groups[0], nil
	}

	parts := strings.Split(path, "/")
	current := &m.db.Content.Root.Groups[0]

	for _, part := range parts {
		found := false
		for i := range current.Groups {
			if current.Groups[i].Name == part {
				current = &current.Groups[i]
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("group '%s' not found in path '%s'", part, path)
		}
	}

	return current, nil
}

// findEntryByPath finds an entry by its full path
func (m *manager) findEntryByPath(path string) (*gokeepasslib.Entry, error) {
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid entry path: %s", path)
	}

	groupPath := strings.Join(parts[:len(parts)-1], "/")
	entryName := parts[len(parts)-1]

	group, err := m.findGroupByPath(groupPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range group.Entries {
		var title string
		for _, value := range entry.Values {
			if value.Key == "Title" {
				title = value.Value.Content
				break
			}
		}
		if title == entryName {
			return &entry, nil
		}
	}

	return nil, fmt.Errorf("entry '%s' not found in group '%s'", entryName, groupPath)
}
func findGroupByName(parentGroup *gokeepasslib.Group, groupName string) (*gokeepasslib.Group, error) {
	if parentGroup == nil {
		return nil, fmt.Errorf("parent group is nil")
	}

	for i := range parentGroup.Groups {
		if parentGroup.Groups[i].Name == groupName {
			return &parentGroup.Groups[i], nil
		}
	}

	return nil, fmt.Errorf("group '%s' not found", groupName)
}

// findEntryByPath finds an entry by its path within a group
// Path format: /entry or /group1/group2/entry
func findEntryByPath(envGroup *gokeepasslib.Group, entryPath string) (*gokeepasslib.Entry, error) {
	if envGroup == nil {
		return nil, fmt.Errorf("environment group is nil")
	}

	// Remove leading slash
	if len(entryPath) > 0 && entryPath[0] == '/' {
		entryPath = entryPath[1:]
	}

	if entryPath == "" {
		return nil, fmt.Errorf("entry path is empty")
	}

	// Split path into components
	components := strings.Split(entryPath, "/")
	if len(components) == 0 {
		return nil, fmt.Errorf("invalid entry path")
	}

	// Navigate through intermediate groups
	currentGroup := envGroup
	for i := 0; i < len(components)-1; i++ {
		groupName := components[i]
		if groupName == "" {
			continue
		}

		found := false
		for j := range currentGroup.Groups {
			if currentGroup.Groups[j].Name == groupName {
				currentGroup = &currentGroup.Groups[j]
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("group '%s' not found in path", groupName)
		}
	}

	// Find entry in the final group
	entryName := components[len(components)-1]
	if entryName == "" {
		return nil, fmt.Errorf("entry name is empty")
	}

	for i := range currentGroup.Entries {
		for _, value := range currentGroup.Entries[i].Values {
			if value.Key == "Title" && value.Value.Content == entryName {
				return &currentGroup.Entries[i], nil
			}
		}
	}

	return nil, fmt.Errorf("entry '%s' not found", entryName)
}

// IsStandardField checks if a field name is a standard KeePass field (case-insensitive)
// Standard fields: Title, UserName, Password, URL, Notes
func (m *manager) IsStandardField(fieldName string) bool {
	standardFields := []string{"Title", "UserName", "Password", "URL", "Notes"}
	fieldLower := strings.ToLower(fieldName)

	for _, standard := range standardFields {
		if strings.ToLower(standard) == fieldLower {
			return true
		}
	}

	return false
}

// SetStandardField sets a standard KeePass field in an entry
// Field name is case-insensitive and will be normalized to standard casing
func (m *manager) SetStandardField(profileName, envName, entryPath, fieldName, value string) error {
	// Check if database is open
	if !m.IsOpen() {
		return fmt.Errorf("database is not open")
	}

	// Validate input parameters
	if profileName == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if envName == "" {
		return fmt.Errorf("environment name cannot be empty")
	}
	if entryPath == "" {
		return fmt.Errorf("entry path cannot be empty")
	}
	if fieldName == "" {
		return fmt.Errorf("field name cannot be empty")
	}

	// Verify it's a standard field
	if !m.IsStandardField(fieldName) {
		return fmt.Errorf("'%s' is not a standard field", fieldName)
	}

	// Normalize field name to standard casing
	standardFields := map[string]string{
		"title":    "Title",
		"username": "UserName",
		"password": "Password",
		"url":      "URL",
		"notes":    "Notes",
	}
	normalizedFieldName := standardFields[strings.ToLower(fieldName)]

	// Find profile group
	profileGroup, err := findGroupByName(&m.db.Content.Root.Groups[0], profileName)
	if err != nil {
		return fmt.Errorf("failed to find profile: %w", err)
	}

	// Find HEAD group
	headGroup, err := findGroupByName(profileGroup, "HEAD")
	if err != nil {
		return fmt.Errorf("failed to find HEAD group: %w", err)
	}

	// Find environment group
	envGroup, err := findGroupByName(headGroup, envName)
	if err != nil {
		return fmt.Errorf("failed to find environment '%s': %w", envName, err)
	}

	// Find entry
	entry, err := findEntryByPath(envGroup, entryPath)
	if err != nil {
		return fmt.Errorf("failed to find entry '%s': %w", entryPath, err)
	}

	// Set or update the standard field
	fieldFound := false
	for i := range entry.Values {
		if entry.Values[i].Key == normalizedFieldName {
			entry.Values[i].Value.Content = value
			fieldFound = true
			break
		}
	}

	// If field doesn't exist, create it
	if !fieldFound {
		newValue := gokeepasslib.ValueData{
			Key:   normalizedFieldName,
			Value: gokeepasslib.V{Content: value},
		}
		entry.Values = append(entry.Values, newValue)
	}

	return nil
}

// SetCustomField sets a custom field in an entry
// Field name casing is preserved exactly as provided
func (m *manager) SetCustomField(profileName, envName, entryPath, fieldName, value string) error {
	// Check if database is open
	if !m.IsOpen() {
		return fmt.Errorf("database is not open")
	}

	// Validate input parameters
	if profileName == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if envName == "" {
		return fmt.Errorf("environment name cannot be empty")
	}
	if entryPath == "" {
		return fmt.Errorf("entry path cannot be empty")
	}
	if fieldName == "" {
		return fmt.Errorf("field name cannot be empty")
	}

	// Verify it's NOT a standard field
	if m.IsStandardField(fieldName) {
		return fmt.Errorf("'%s' is a standard field, use SetStandardField instead", fieldName)
	}

	// Find profile group
	profileGroup, err := findGroupByName(&m.db.Content.Root.Groups[0], profileName)
	if err != nil {
		return fmt.Errorf("failed to find profile: %w", err)
	}

	// Find HEAD group
	headGroup, err := findGroupByName(profileGroup, "HEAD")
	if err != nil {
		return fmt.Errorf("failed to find HEAD group: %w", err)
	}

	// Find environment group
	envGroup, err := findGroupByName(headGroup, envName)
	if err != nil {
		return fmt.Errorf("failed to find environment '%s': %w", envName, err)
	}

	// Find entry
	entry, err := findEntryByPath(envGroup, entryPath)
	if err != nil {
		return fmt.Errorf("failed to find entry '%s': %w", entryPath, err)
	}

	// Set or update the custom field (preserve exact casing)
	fieldFound := false
	for i := range entry.Values {
		if entry.Values[i].Key == fieldName {
			entry.Values[i].Value.Content = value
			fieldFound = true
			break
		}
	}

	// If field doesn't exist, create it
	if !fieldFound {
		newValue := gokeepasslib.ValueData{
			Key:   fieldName,
			Value: gokeepasslib.V{Content: value},
		}
		entry.Values = append(entry.Values, newValue)
	}

	return nil
}

// CreateAttachment creates or updates an attachment in an entry
// Attachments in gokeepasslib use a BinaryReference system where:
// 1. Binary data is stored in db.Content.Meta.Binaries
// 2. Entry references binary by ID via entry.Binaries (BinaryReference)
func (m *manager) CreateAttachment(profileName, envName, entryPath, attachmentName string, data []byte) error {
	// Check if database is open
	if !m.IsOpen() {
		return fmt.Errorf("database is not open")
	}

	// Validate input parameters
	if profileName == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if envName == "" {
		return fmt.Errorf("environment name cannot be empty")
	}
	if entryPath == "" {
		return fmt.Errorf("entry path cannot be empty")
	}
	if attachmentName == "" {
		return fmt.Errorf("attachment name cannot be empty")
	}
	if data == nil {
		return fmt.Errorf("attachment data cannot be nil")
	}

	// Find profile group
	profileGroup, err := findGroupByName(&m.db.Content.Root.Groups[0], profileName)
	if err != nil {
		return fmt.Errorf("failed to find profile: %w", err)
	}

	// Find HEAD group
	headGroup, err := findGroupByName(profileGroup, "HEAD")
	if err != nil {
		return fmt.Errorf("failed to find HEAD group: %w", err)
	}

	// Find environment group
	envGroup, err := findGroupByName(headGroup, envName)
	if err != nil {
		return fmt.Errorf("failed to find environment '%s': %w", envName, err)
	}

	// Find entry
	entry, err := findEntryByPath(envGroup, entryPath)
	if err != nil {
		return fmt.Errorf("failed to find entry '%s': %w", entryPath, err)
	}

	// Check if attachment with same name already exists
	for i := range entry.Binaries {
		if entry.Binaries[i].Name == attachmentName {
			// According to .context, if something already exists, it should not be touched
			// Return success silently (idempotent behavior)
			return nil
		}
	}

	// Generate unique binary ID
	// Use the next available ID in db.Content.Meta.Binaries
	binaryID := len(m.db.Content.Meta.Binaries)

	// Create binary data in Meta.Binaries
	binary := gokeepasslib.Binary{
		ID:      binaryID,
		Content: data,
	}
	m.db.Content.Meta.Binaries = append(m.db.Content.Meta.Binaries, binary)

	// Create binary reference in entry using the helper function
	binaryRef := gokeepasslib.NewBinaryReference(attachmentName, binaryID)
	entry.Binaries = append(entry.Binaries, binaryRef)

	return nil
}

// FieldExists checks if a field exists in an entry (standard or custom field)
// For standard fields, comparison is case-insensitive
// For custom fields, comparison is case-sensitive
func (m *manager) FieldExists(profileName, envName, entryPath, fieldName string) (bool, error) {
	// Check if database is open
	if !m.IsOpen() {
		return false, fmt.Errorf("database is not open")
	}

	// Validate input parameters
	if profileName == "" {
		return false, fmt.Errorf("profile name cannot be empty")
	}
	if envName == "" {
		return false, fmt.Errorf("environment name cannot be empty")
	}
	if entryPath == "" {
		return false, fmt.Errorf("entry path cannot be empty")
	}
	if fieldName == "" {
		return false, fmt.Errorf("field name cannot be empty")
	}

	// Find profile group
	profileGroup, err := findGroupByName(&m.db.Content.Root.Groups[0], profileName)
	if err != nil {
		return false, fmt.Errorf("failed to find profile: %w", err)
	}

	// Find HEAD group
	headGroup, err := findGroupByName(profileGroup, "HEAD")
	if err != nil {
		return false, fmt.Errorf("failed to find HEAD group: %w", err)
	}

	// Find environment group
	envGroup, err := findGroupByName(headGroup, envName)
	if err != nil {
		return false, fmt.Errorf("failed to find environment '%s': %w", envName, err)
	}

	// Find entry
	entry, err := findEntryByPath(envGroup, entryPath)
	if err != nil {
		return false, fmt.Errorf("failed to find entry '%s': %w", entryPath, err)
	}

	// Check if it's an attachment field
	if strings.HasPrefix(fieldName, "attachments/") {
		// Extract attachment name
		attachmentName := strings.TrimPrefix(fieldName, "attachments/")

		// Check in entry binaries
		for _, binary := range entry.Binaries {
			if binary.Name == attachmentName {
				return true, nil
			}
		}
		return false, nil
	}

	// Check if field exists (standard or custom)
	isStandard := m.IsStandardField(fieldName)

	for _, value := range entry.Values {
		if isStandard {
			// Case-insensitive comparison for standard fields
			if strings.ToLower(value.Key) == strings.ToLower(fieldName) {
				return true, nil
			}
		} else {
			// Case-sensitive comparison for custom fields
			if value.Key == fieldName {
				return true, nil
			}
		}
	}

	return false, nil
}

// ListProfileTreeGroups lists all tree groups (HEAD, v1, v2, etc.) for a given profile
// Returns the list of tree group names
func (m *manager) ListProfileTreeGroups(profileName string) ([]string, error) {
	// Validate session
	if m.db == nil {
		return nil, fmt.Errorf("database not open")
	}

	// Validate input
	if profileName == "" {
		return nil, fmt.Errorf("profile name cannot be empty")
	}

	// Find profile group
	if len(m.db.Content.Root.Groups) == 0 {
		return nil, fmt.Errorf("no groups in database")
	}

	profileGroup, err := findGroupByName(&m.db.Content.Root.Groups[0], profileName)
	if err != nil {
		return nil, fmt.Errorf("profile '%s' not found: %w", profileName, err)
	}

	// List all direct children of the profile (tree groups: HEAD, v1, v2, etc.)
	var treeGroups []string
	for _, group := range profileGroup.Groups {
		treeGroups = append(treeGroups, group.Name)
	}

	return treeGroups, nil
}

// GetTreeGroupEntryField retrieves a field value from an entry within a tree group
// profileName: the profile name
// treeGroup: the tree group name (e.g., "HEAD", "v1", "v2")
// entryPath: path to the entry (e.g., "metadata" or "/env/path/to/entry")
// fieldName: the field name to retrieve
func (m *manager) GetTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName string) (string, error) {
	// Validate session
	if m.db == nil {
		return "", fmt.Errorf("database not open")
	}

	// Validate input
	if profileName == "" {
		return "", fmt.Errorf("profile name cannot be empty")
	}
	if treeGroup == "" {
		return "", fmt.Errorf("tree group name cannot be empty")
	}
	if entryPath == "" {
		return "", fmt.Errorf("entry path cannot be empty")
	}
	if fieldName == "" {
		return "", fmt.Errorf("field name cannot be empty")
	}

	// Find profile group
	if len(m.db.Content.Root.Groups) == 0 {
		return "", fmt.Errorf("no groups in database")
	}

	profileGroup, err := findGroupByName(&m.db.Content.Root.Groups[0], profileName)
	if err != nil {
		return "", fmt.Errorf("profile '%s' not found: %w", profileName, err)
	}

	// Find tree group (HEAD, v1, v2, etc.)
	treeGroupObj, err := findGroupByName(profileGroup, treeGroup)
	if err != nil {
		return "", fmt.Errorf("tree group '%s' not found in profile '%s': %w", treeGroup, profileName, err)
	}

	// Find entry by path
	entry, err := findEntryByPath(treeGroupObj, entryPath)
	if err != nil {
		return "", fmt.Errorf("entry '%s' not found in tree group '%s': %w", entryPath, treeGroup, err)
	}

	// Find field in entry
	isStandard := m.IsStandardField(fieldName)

	for _, value := range entry.Values {
		if isStandard {
			// Case-insensitive comparison for standard fields
			if strings.ToLower(value.Key) == strings.ToLower(fieldName) {
				return value.Value.Content, nil
			}
		} else {
			// Case-sensitive comparison for custom fields
			if value.Key == fieldName {
				return value.Value.Content, nil
			}
		}
	}

	return "", fmt.Errorf("field '%s' not found in entry '%s'", fieldName, entryPath)
}

// CloneTreeGroup clones a source tree group to a new tree group within the same profile
// This performs a recursive deep copy of all subgroups and entries
func (m *manager) CloneTreeGroup(profileName, sourceTreeGroup, targetTreeGroup string) error {
	// Validate session
	if m.db == nil {
		return fmt.Errorf("database not open")
	}

	// Validate input
	if profileName == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if sourceTreeGroup == "" {
		return fmt.Errorf("source tree group cannot be empty")
	}
	if targetTreeGroup == "" {
		return fmt.Errorf("target tree group cannot be empty")
	}

	// Find profile group
	if len(m.db.Content.Root.Groups) == 0 {
		return fmt.Errorf("no groups in database")
	}

	profileGroup, err := findGroupByName(&m.db.Content.Root.Groups[0], profileName)
	if err != nil {
		return fmt.Errorf("profile '%s' not found: %w", profileName, err)
	}

	// Find source tree group
	sourceGroup, err := findGroupByName(profileGroup, sourceTreeGroup)
	if err != nil {
		return fmt.Errorf("source tree group '%s' not found in profile '%s': %w", sourceTreeGroup, profileName, err)
	}

	// Check if target already exists
	_, err = findGroupByName(profileGroup, targetTreeGroup)
	if err == nil {
		return fmt.Errorf("target tree group '%s' already exists in profile '%s'", targetTreeGroup, profileName)
	}

	// Deep clone the source group
	clonedGroup := deepCloneGroup(sourceGroup)

	// Rename the cloned group to target name
	clonedGroup.Name = targetTreeGroup

	// Add cloned group to profile
	profileGroup.Groups = append(profileGroup.Groups, clonedGroup)

	return nil
}

// SetTreeGroupEntryField sets a field value in an entry within a tree group
func (m *manager) SetTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName, value string) error {
	// Validate session
	if m.db == nil {
		return fmt.Errorf("database not open")
	}

	// Validate input
	if profileName == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if treeGroup == "" {
		return fmt.Errorf("tree group cannot be empty")
	}
	if entryPath == "" {
		return fmt.Errorf("entry path cannot be empty")
	}
	if fieldName == "" {
		return fmt.Errorf("field name cannot be empty")
	}

	// Find profile group
	if len(m.db.Content.Root.Groups) == 0 {
		return fmt.Errorf("no groups in database")
	}

	profileGroup, err := findGroupByName(&m.db.Content.Root.Groups[0], profileName)
	if err != nil {
		return fmt.Errorf("profile '%s' not found: %w", profileName, err)
	}

	// Find tree group
	treeGroupObj, err := findGroupByName(profileGroup, treeGroup)
	if err != nil {
		return fmt.Errorf("tree group '%s' not found in profile '%s': %w", treeGroup, profileName, err)
	}

	// Find entry by path
	entry, err := findEntryByPath(treeGroupObj, entryPath)
	if err != nil {
		return fmt.Errorf("entry '%s' not found in tree group '%s': %w", entryPath, treeGroup, err)
	}

	// Check if field is standard
	isStandard := m.IsStandardField(fieldName)

	// Set or update the field
	fieldFound := false
	for i := range entry.Values {
		if isStandard {
			// Case-insensitive comparison for standard fields
			if strings.ToLower(entry.Values[i].Key) == strings.ToLower(fieldName) {
				entry.Values[i].Value.Content = value
				fieldFound = true
				break
			}
		} else {
			// Case-sensitive comparison for custom fields
			if entry.Values[i].Key == fieldName {
				entry.Values[i].Value.Content = value
				fieldFound = true
				break
			}
		}
	}

	// If field doesn't exist, create it
	if !fieldFound {
		newValue := gokeepasslib.ValueData{
			Key:   fieldName,
			Value: gokeepasslib.V{Content: value},
		}
		entry.Values = append(entry.Values, newValue)
	}

	return nil
}

// deepCloneGroup performs a deep clone of a group and all its subgroups/entries
func deepCloneGroup(source *gokeepasslib.Group) gokeepasslib.Group {
	cloned := gokeepasslib.Group{
		UUID:                    gokeepasslib.NewUUID(),
		Name:                    source.Name,
		Notes:                   source.Notes,
		IconID:                  source.IconID,
		Times:                   source.Times,
		IsExpanded:              source.IsExpanded,
		DefaultAutoTypeSequence: source.DefaultAutoTypeSequence,
		EnableAutoType:          source.EnableAutoType,
		EnableSearching:         source.EnableSearching,
		LastTopVisibleEntry:     source.LastTopVisibleEntry,
	}

	// Clone entries
	cloned.Entries = make([]gokeepasslib.Entry, len(source.Entries))
	for i, entry := range source.Entries {
		cloned.Entries[i] = deepCloneEntry(&entry)
	}

	// Clone subgroups recursively
	cloned.Groups = make([]gokeepasslib.Group, len(source.Groups))
	for i, group := range source.Groups {
		cloned.Groups[i] = deepCloneGroup(&group)
	}

	return cloned
}

// deepCloneEntry performs a deep clone of an entry
func deepCloneEntry(source *gokeepasslib.Entry) gokeepasslib.Entry {
	cloned := gokeepasslib.Entry{
		UUID:            gokeepasslib.NewUUID(),
		IconID:          source.IconID,
		ForegroundColor: source.ForegroundColor,
		BackgroundColor: source.BackgroundColor,
		OverrideURL:     source.OverrideURL,
		Tags:            source.Tags,
		Times:           source.Times,
	}

	// Clone values
	cloned.Values = make([]gokeepasslib.ValueData, len(source.Values))
	for i, value := range source.Values {
		cloned.Values[i] = gokeepasslib.ValueData{
			Key:   value.Key,
			Value: gokeepasslib.V{Content: value.Value.Content, Protected: value.Value.Protected},
		}
	}

	// Clone binaries if any
	if len(source.Binaries) > 0 {
		cloned.Binaries = make([]gokeepasslib.BinaryReference, len(source.Binaries))
		copy(cloned.Binaries, source.Binaries)
	}

	return cloned
}

// TreeGroupExists checks if a tree group exists under a profile
func (m *manager) TreeGroupExists(profileName, treeGroup string) (bool, error) {
	if m.db == nil {
		return false, fmt.Errorf("database not open")
	}

	// Validate input
	if profileName == "" {
		return false, fmt.Errorf("profile name cannot be empty")
	}
	if treeGroup == "" {
		return false, fmt.Errorf("tree group name cannot be empty")
	}

	// Check if root group exists
	if len(m.db.Content.Root.Groups) == 0 {
		return false, nil
	}

	rootGroup := &m.db.Content.Root.Groups[0]

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

	// Try to find tree group under profile
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == treeGroup {
			return true, nil
		}
	}

	return false, nil
}

// RenameTreeGroup renames a tree group under a profile
func (m *manager) RenameTreeGroup(profileName, oldName, newName string) error {
	if m.db == nil {
		return fmt.Errorf("database not open")
	}

	// Validate input
	if profileName == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if oldName == "" {
		return fmt.Errorf("old name cannot be empty")
	}
	if newName == "" {
		return fmt.Errorf("new name cannot be empty")
	}

	// Check if root group exists
	if len(m.db.Content.Root.Groups) == 0 {
		return fmt.Errorf("root group not found")
	}

	rootGroup := &m.db.Content.Root.Groups[0]

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

	// Find tree group to rename
	var treeGroupFound bool
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == oldName {
			profileGroup.Groups[i].Name = newName
			treeGroupFound = true
			break
		}
	}

	if !treeGroupFound {
		return fmt.Errorf("tree group '%s' not found in profile '%s'", oldName, profileName)
	}

	return nil
}

// DeleteTreeGroup deletes a tree group under a profile
func (m *manager) DeleteTreeGroup(profileName, treeGroup string) error {
	if m.db == nil {
		return fmt.Errorf("database not open")
	}

	// Validate input
	if profileName == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if treeGroup == "" {
		return fmt.Errorf("tree group name cannot be empty")
	}

	// Check if root group exists
	if len(m.db.Content.Root.Groups) == 0 {
		return fmt.Errorf("root group not found")
	}

	rootGroup := &m.db.Content.Root.Groups[0]

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

	// Find and delete tree group
	var treeGroupIndex = -1
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == treeGroup {
			treeGroupIndex = i
			break
		}
	}

	if treeGroupIndex == -1 {
		return fmt.Errorf("tree group '%s' not found in profile '%s'", treeGroup, profileName)
	}

	// Remove tree group from slice
	profileGroup.Groups = append(profileGroup.Groups[:treeGroupIndex], profileGroup.Groups[treeGroupIndex+1:]...)

	return nil
}
