// Package keepass provides KeePass database implementation following SOLID principles
// This is the main implementation file for the keepass package
package keepass

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
)

// KeePass implements SecretsManager interface following SOLID principles
type KeePass struct {
	// Dependencies injected (DIP - Dependency Inversion Principle)
	pathHandler secrets.PathHandler
	authHandler secrets.AuthHandler
	dataHandler secrets.DataHandler
	
	// State
	databasePath string
	keyfilePath  string
	database     *gokeepasslib.Database
	credentials  *gokeepasslib.DBCredentials
	isOpen       bool
}

// Compile-time check (LSP - Liskov Substitution Principle)
var _ secrets.SecretsManager = (*KeePass)(nil)

// New creates a KeePass instance following SOLID principles
// This version uses proper dependency injection (DIP - Dependency Inversion Principle)
func New(dbPath string) (*KeePass, error) {
	// Create default implementations (factory method pattern)
	pathHandler := NewPathHandler()
	authHandler := NewAuthHandler()
	dataHandler := NewDataHandler()
	
	return NewWithDependencies(dbPath, pathHandler, authHandler, dataHandler)
}

// NewWithDependencies creates a KeePass instance with injected dependencies
// This allows complete control over dependencies for testing and flexibility (DIP)
func NewWithDependencies(dbPath string, 
	pathHandler secrets.PathHandler,
	authHandler secrets.AuthHandler, 
	dataHandler secrets.DataHandler) (*KeePass, error) {
	
	if err := pathHandler.ValidatePath(dbPath); err != nil {
		return nil, err
	}

	return &KeePass{
		// Dependencies are now injected, not created (DIP)
		pathHandler:  pathHandler,
		authHandler:  authHandler,
		dataHandler:  dataHandler,
		databasePath: pathHandler.NormalizePath(dbPath),
		database:     nil,
		credentials:  nil,
		isOpen:       false,
	}, nil
}

// CreateDB creates a new database (SRP - Single Responsibility)
func (k *KeePass) CreateDB(username, password string, createKeyFile bool) error {
	if password == "" {
		return errors.New("password cannot be empty")
	}

	// Create new database
	k.database = gokeepasslib.NewDatabase()
	
	// Customize the root group name
	if len(k.database.Content.Root.Groups) > 0 {
		k.database.Content.Root.Groups[0].Name = "SECRETS_YOHNAH"
		
		// Remove the default "Sample Entry" created by gokeepasslib
		if len(k.database.Content.Root.Groups[0].Entries) > 0 {
			// Clear all default entries - we want a clean database
			k.database.Content.Root.Groups[0].Entries = []gokeepasslib.Entry{}
		}
	}
	
	// The NewDatabase() already creates a proper structure with a default group
	// We don't need to override it completely, just ensure it's ready to use

	// Setup credentials using gokeepasslib functions
	if createKeyFile {
		k.keyfilePath = k.pathHandler.GetKeyFilePath(k.databasePath)
		keyData, err := k.authHandler.GenerateKeyFile()
		if err != nil {
			return err
		}
		
		// Save keyfile to disk
		if err := os.WriteFile(k.keyfilePath, keyData, 0600); err != nil {
			return fmt.Errorf("failed to save keyfile: %v", err)
		}
		
		// Create credentials with both password and key
		k.credentials, err = gokeepasslib.NewPasswordAndKeyDataCredentials(password, keyData)
		if err != nil {
			return fmt.Errorf("failed to create credentials: %v", err)
		}
	} else {
		// Create credentials with password only
		k.credentials = gokeepasslib.NewPasswordCredentials(password)
	}

	// Create directory if needed
	dir := filepath.Dir(k.databasePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Save database
	k.isOpen = true
	if err := k.Save(); err != nil {
		return fmt.Errorf("failed to save database: %v", err)
	}

	return nil
}

// CreateDBWithKeyData creates a new database with provided keyfile data
func (k *KeePass) CreateDBWithKeyData(username, password string, keyData []byte) error {
	if password == "" {
		return errors.New("password cannot be empty")
	}
	if keyData == nil {
		return errors.New("keyfile data cannot be nil")
	}

	// Create new database
	k.database = gokeepasslib.NewDatabase()
	
	// Customize the root group name
	if len(k.database.Content.Root.Groups) > 0 {
		k.database.Content.Root.Groups[0].Name = "SECRETS_YOHNAH"
		
		// Remove the default "Sample Entry" created by gokeepasslib
		if len(k.database.Content.Root.Groups[0].Entries) > 0 {
			// Clear all default entries - we want a clean database
			k.database.Content.Root.Groups[0].Entries = []gokeepasslib.Entry{}
		}
	}
	
	// Create credentials with both password and provided key data
	var err error
	k.credentials, err = gokeepasslib.NewPasswordAndKeyDataCredentials(password, keyData)
	if err != nil {
		return fmt.Errorf("failed to create credentials: %v", err)
	}

	// Create directory if needed
	dir := filepath.Dir(k.databasePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Save database
	k.isOpen = true
	if err := k.Save(); err != nil {
		return fmt.Errorf("failed to save database: %v", err)
	}

	return nil
}

// Open opens database (delegates to handlers - SRP)
func (k *KeePass) Open(username, password, keyFilePath string) error {
	if password == "" && keyFilePath == "" {
		return errors.New("either password or keyfile must be provided")
	}

	// Setup credentials using gokeepasslib functions
	var err error
	if keyFilePath != "" {
		keyData, loadErr := k.authHandler.LoadKeyFile(keyFilePath)
		if loadErr != nil {
			return fmt.Errorf("failed to load keyfile: %v", loadErr)
		}
		
		// Create credentials with both password and key
		k.credentials, err = gokeepasslib.NewPasswordAndKeyDataCredentials(password, keyData)
		if err != nil {
			return fmt.Errorf("failed to create credentials: %v", err)
		}
		k.keyfilePath = keyFilePath
	} else {
		// Create credentials with password only
		k.credentials = gokeepasslib.NewPasswordCredentials(password)
	}

	// Check if database file exists
	if _, err := os.Stat(k.databasePath); os.IsNotExist(err) {
		return fmt.Errorf("database file does not exist: %s", k.databasePath)
	}

	// Open database file
	file, err := os.Open(k.databasePath)
	if err != nil {
		return fmt.Errorf("failed to open database file: %v", err)
	}
	defer file.Close()

	// Parse database
	db := gokeepasslib.NewDatabase()
	db.Credentials = k.credentials
	err = gokeepasslib.NewDecoder(file).Decode(db)
	if err != nil {
		return fmt.Errorf("failed to decode database: %v", err)
	}

	// Unlock database
	err = db.UnlockProtectedEntries()
	if err != nil {
		return fmt.Errorf("failed to unlock database: %v", err)
	}

	k.database = db
	k.isOpen = true
	
	return nil
}

// Close closes database
func (k *KeePass) Close() {
	if k.database != nil && k.isOpen {
		k.database.LockProtectedEntries()
	}
	k.isOpen = false
	k.database = nil
	k.credentials = nil
}

// CreateGroup creates a new group at the specified path
func (k *KeePass) CreateGroup(groupPath string) error {
	if !k.isOpen {
		return errors.New("database is not open")
	}
	
	if groupPath == "" {
		return errors.New("group path cannot be empty")
	}
	
	// Clean and split the path
	groupPath = strings.Trim(groupPath, "/")
	if groupPath == "" {
		return errors.New("invalid group path")
	}
	
	pathParts := strings.Split(groupPath, "/")
	
	// Start from the first group in the root (typically "NewDatabase")
	if len(k.database.Content.Root.Groups) == 0 {
		return errors.New("no root groups found in database")
	}
	
	currentGroup := &k.database.Content.Root.Groups[0]
	
	// Navigate/create each level of the path
	for _, groupName := range pathParts {
		if groupName == "" {
			continue
		}
		
		// Look for existing group
		var foundGroup *gokeepasslib.Group
		for i := range currentGroup.Groups {
			if currentGroup.Groups[i].Name == groupName {
				foundGroup = &currentGroup.Groups[i]
				break
			}
		}
		
		// If group doesn't exist, create it
		if foundGroup == nil {
			newGroup := gokeepasslib.NewGroup()
			newGroup.Name = groupName
			currentGroup.Groups = append(currentGroup.Groups, newGroup)
			foundGroup = &currentGroup.Groups[len(currentGroup.Groups)-1]
		}
		
		currentGroup = foundGroup
	}
	
	return nil
}

// IsOpen returns open status
func (k *KeePass) IsOpen() bool {
	return k.isOpen
}

// Save saves database
func (k *KeePass) Save() error {
	if !k.IsOpen() || k.database == nil || k.credentials == nil {
		return errors.New("database is not open")
	}

	// Lock entries before saving
	k.database.LockProtectedEntries()

	// Create directory if needed
	dir := filepath.Dir(k.databasePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Create/open file for writing
	file, err := os.Create(k.databasePath)
	if err != nil {
		return fmt.Errorf("failed to create database file: %v", err)
	}
	defer file.Close()

	// Encode and save database
	k.database.Credentials = k.credentials
	keepassEncoder := gokeepasslib.NewEncoder(file)
	err = keepassEncoder.Encode(k.database)
	if err != nil {
		return fmt.Errorf("failed to encode database: %v", err)
	}

	// Unlock entries again for continued use
	k.database.UnlockProtectedEntries()

	return nil
}

// Get retrieves data with payload support for Vault integration (OCP - Open/Closed)
func (k *KeePass) Get(entryPath string, key *string, payload map[string]interface{}) (interface{}, error) {
	if !k.IsOpen() || k.database == nil {
		return nil, errors.New("database is not open")
	}

	// TODO: payload ready for Vault CSR/TTL integration (OCP)
	
	// Find entry in database
	entry, err := k.findEntry(entryPath)
	if err != nil {
		return nil, err
	}

	if key == nil {
		// Return all data as map
		result := make(map[string]string)
		
		// Add all values
		for _, value := range entry.Values {
			result[value.Key] = value.Value.Content
		}
		
		// Add binaries as file references
		for _, binary := range entry.Binaries {
			binaryData := binary.Find(k.database)
			if binaryData != nil {
				result[binary.Name] = fmt.Sprintf("[BINARY:%d bytes]", len(binaryData.Content))
			}
		}
		
		return result, nil
	} else {
		// Return specific key
		// First check values
		for _, value := range entry.Values {
			if value.Key == *key {
				return value.Value.Content, nil
			}
		}
		
		// Then check binaries
		for _, binary := range entry.Binaries {
			if binary.Name == *key {
				binaryData := binary.Find(k.database)
				if binaryData != nil {
					return binaryData.Content, nil
				}
			}
		}
		
		return nil, fmt.Errorf("key '%s' not found in entry '%s'", *key, entryPath)
	}
}

// Write stores data (delegates to data handler - SRP)
func (k *KeePass) Write(entryPath, key string, value interface{}, isFile bool) error {
	if !k.IsOpen() || k.database == nil {
		return errors.New("database is not open")
	}

	// Find or create entry
	entry, err := k.findOrCreateEntry(entryPath)
	if err != nil {
		return err
	}

	// Convert value to string
	valueStr := fmt.Sprintf("%v", value)

	if isFile {
		// Handle binary data
		var content []byte
		if str, ok := value.(string); ok {
			content = []byte(str)
		} else if bytes, ok := value.([]byte); ok {
			content = bytes
		} else {
			content = []byte(valueStr)
		}

		// Remove existing binary with same key
		for i, binary := range entry.Binaries {
			if binary.Name == key {
				entry.Binaries = append(entry.Binaries[:i], entry.Binaries[i+1:]...)
				break
			}
		}

		// Add binary to database and create reference
		binary := k.database.AddBinary(content)
		binaryRef := gokeepasslib.NewBinaryReference(key, binary.ID)
		entry.Binaries = append(entry.Binaries, binaryRef)
	} else {
		// Handle text data
		// Remove existing value with same key
		for i, val := range entry.Values {
			if val.Key == key {
				entry.Values = append(entry.Values[:i], entry.Values[i+1:]...)
				break
			}
		}

		// Add new value
		isProtected := (key == "Password" || key == "password")
		entry.Values = append(entry.Values, gokeepasslib.ValueData{
			Key: key,
			Value: gokeepasslib.V{
				Content:   valueStr,
				Protected: wrappers.NewBoolWrapper(isProtected),
			},
		})
	}

	return k.Save()
}

// Delete removes data
func (k *KeePass) Delete(entryPath string, key *string) error {
	if !k.IsOpen() || k.database == nil {
		return errors.New("database is not open")
	}

	if key == nil {
		// Delete entire entry
		return k.deleteEntry(entryPath)
	} else {
		// Delete specific key
		entry, err := k.findEntry(entryPath)
		if err != nil {
			return err
		}

		// Remove from values
		for i, value := range entry.Values {
			if value.Key == *key {
				entry.Values = append(entry.Values[:i], entry.Values[i+1:]...)
				return k.Save()
			}
		}

		// Remove from binaries
		for i, binary := range entry.Binaries {
			if binary.Name == *key {
				entry.Binaries = append(entry.Binaries[:i], entry.Binaries[i+1:]...)
				return k.Save()
			}
		}

		return fmt.Errorf("key '%s' not found in entry '%s'", *key, entryPath)
	}
}

// List returns all entries  
func (k *KeePass) List() ([]string, error) {
	if !k.IsOpen() || k.database == nil {
		return nil, errors.New("database is not open")
	}

	var entries []string

	// Walk through all groups recursively to find entries
	for _, group := range k.database.Content.Root.Groups {
		k.walkGroup(group, "", &entries)
	}

	// Defensive check: in case future versions allow root-level entries
	// This would require extending RootData struct, but we check defensively
	// Note: Current gokeepasslib v3 doesn't support this, but we stay prepared

	return entries, nil
}

// walkGroup recursively walks through groups to collect entry paths
func (k *KeePass) walkGroup(group gokeepasslib.Group, path string, entries *[]string) {
	currentPath := path
	if group.Name != "" {
		if currentPath != "" {
			currentPath += "/"
		}
		currentPath += group.Name
	}

	// Add entries from this group
	for _, entry := range group.Entries {
		title := ""
		for _, value := range entry.Values {
			if value.Key == "Title" {
				title = value.Value.Content
				break
			}
		}
		if title != "" {
			entryPath := title
			if currentPath != "" {
				entryPath = currentPath + "/" + title
			}
			*entries = append(*entries, entryPath)
		}
	}

	// Recursively process subgroups
	for _, subGroup := range group.Groups {
		k.walkGroup(subGroup, currentPath, entries)
	}
}

// Helper methods for real gokeepasslib operations

// findEntry finds an entry by its path/title
func (k *KeePass) findEntry(entryPath string) (*gokeepasslib.Entry, error) {
	if k.database == nil {
		return nil, errors.New("database not initialized")
	}

	// Check entries in groups
	for _, group := range k.database.Content.Root.Groups {
		entry := k.findEntryInGroup(group, entryPath)
		if entry != nil {
			return entry, nil
		}
	}

	return nil, fmt.Errorf("entry not found: %s", entryPath)
}

// findEntryInGroup recursively searches for an entry in a group
func (k *KeePass) findEntryInGroup(group gokeepasslib.Group, entryPath string) *gokeepasslib.Entry {
	// Check entries in this group
	for i := range group.Entries {
		entry := &group.Entries[i]
		for _, value := range entry.Values {
			if value.Key == "Title" && value.Value.Content == entryPath {
				return entry
			}
		}
	}

	// Recursively check subgroups
	for _, subGroup := range group.Groups {
		entry := k.findEntryInGroup(subGroup, entryPath)
		if entry != nil {
			return entry
		}
	}

	return nil
}

// findOrCreateEntry finds an existing entry or creates a new one
func (k *KeePass) findOrCreateEntry(entryPath string) (*gokeepasslib.Entry, error) {
	if k.database == nil {
		return nil, errors.New("database not initialized")
	}

	// Try to find existing entry
	entry, err := k.findEntry(entryPath)
	if err == nil {
		return entry, nil
	}

	// Create new entry
	newEntry := gokeepasslib.NewEntry()
	newEntry.Values = append(newEntry.Values, gokeepasslib.ValueData{
		Key: "Title",
		Value: gokeepasslib.V{
			Content: entryPath,
		},
	})

	// Add to first available group (or create one if none exists)
	if len(k.database.Content.Root.Groups) == 0 {
		// Create default group if none exists
		defaultGroup := gokeepasslib.NewGroup()
		defaultGroup.Name = "Root"
		defaultGroup.UUID = gokeepasslib.NewUUID()
		k.database.Content.Root.Groups = append(k.database.Content.Root.Groups, defaultGroup)
	}

	// Add entry to first group
	k.database.Content.Root.Groups[0].Entries = append(k.database.Content.Root.Groups[0].Entries, newEntry)

	// Return reference to the newly added entry
	lastIndex := len(k.database.Content.Root.Groups[0].Entries) - 1
	return &k.database.Content.Root.Groups[0].Entries[lastIndex], nil
}

// deleteEntry removes an entire entry
func (k *KeePass) deleteEntry(entryPath string) error {
	if k.database == nil {
		return errors.New("database not initialized")
	}

	// Check entries in groups (including root-level groups)
	for i := range k.database.Content.Root.Groups {
		if k.deleteEntryFromGroup(&k.database.Content.Root.Groups[i], entryPath) {
			return k.Save()
		}
	}

	return fmt.Errorf("entry not found: %s", entryPath)
}

// deleteEntryFromGroup recursively removes an entry from a group
func (k *KeePass) deleteEntryFromGroup(group *gokeepasslib.Group, entryPath string) bool {
	// Check entries in this group
	for i, entry := range group.Entries {
		for _, value := range entry.Values {
			if value.Key == "Title" && value.Value.Content == entryPath {
				// Remove from group entries
				group.Entries = append(group.Entries[:i], group.Entries[i+1:]...)
				return true
			}
		}
	}

	// Recursively check subgroups
	for i := range group.Groups {
		if k.deleteEntryFromGroup(&group.Groups[i], entryPath) {
			return true
		}
	}

	return false
}

// GetKeyFilePath returns the path to the key file if one was generated/used
func (k *KeePass) GetKeyFilePath() string {
	return k.keyfilePath
}

// OpenWithKeyData opens an existing KeePass database with password and keyfile data
func (k *KeePass) OpenWithKeyData(password string, keyData []byte) error {
	if k.database != nil {
		return fmt.Errorf("database already loaded")
	}
	
	// Read the database file
	file, err := os.Open(k.databasePath)
	if err != nil {
		return fmt.Errorf("cannot open database file: %v", err)
	}
	defer file.Close()
	
	// Create credentials with password and keyfile data
	credentials, err := gokeepasslib.NewPasswordAndKeyDataCredentials(password, keyData)
	if err != nil {
		return fmt.Errorf("failed to create credentials: %v", err)
	}
	
	// Decode the database
	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials
	err = gokeepasslib.NewDecoder(file).Decode(db)
	if err != nil {
		return fmt.Errorf("failed to decode database: %v", err)
	}
	
	// Unlock the database
	err = db.UnlockProtectedEntries()
	if err != nil {
		return fmt.Errorf("failed to unlock database: %v", err)
	}
	
	k.database = db
	k.credentials = credentials
	k.isOpen = true
	return nil
}

// GroupExists checks if a group with the given name exists in the database
func (k *KeePass) GroupExists(groupName string) (bool, error) {
	if k.database == nil {
		return false, fmt.Errorf("database not loaded")
	}
	
	// Check if group exists in root groups
	return k.findGroupByName(groupName, &k.database.Content.Root.Groups[0]), nil
}

// findGroupByName recursively searches for a group by name
func (k *KeePass) findGroupByName(groupName string, group *gokeepasslib.Group) bool {
	// Check current group
	if group.Name == groupName {
		return true
	}
	
	// Check subgroups recursively
	for i := range group.Groups {
		if k.findGroupByName(groupName, &group.Groups[i]) {
			return true
		}
	}
	
	return false
}