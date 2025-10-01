package cli

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/tobischo/gokeepasslib/v3"
)

// KeePass standard fields (case-insensitive mapping)
var standardFields = map[string]string{
	"title":    "Title",
	"username": "UserName", 
	"password": "Password",
	"url":      "URL",
	"notes":    "Notes",
}

// EntryCreationResult contiene información sobre las entradas creadas
// EntryCreationResult tracks what was created during environment and entry creation
type EntryCreationResult struct {
	NewEntries     int
	ProfileName    string
	CreatedEntries int
	TotalEntries   int
}

// SnapshotCreationResult contains information about a created snapshot
type SnapshotCreationResult struct {
	CreatedVersion string // The version that was created from HEAD (e.g., "v3")
	NewHeadVersion string // The new version that HEAD is now at (e.g., "v4")
}

// KeePassManager interface follows ISP - Interface Segregation Principle
type KeePassManager interface {
	CreateDatabase(dbPath, keyfilePath, password string) error
	DatabaseExists(dbPath string) bool
	KeyfileExists(keyfilePath string) bool
	GenerateKeyfile(keyfilePath string) error
	ValidatePaths(dbPath, keyfilePath string) error
	EnsureProfileStructure(dbPath, keyfilePath, password, profile string) error
	CreateEnvironmentsAndEntries(dbPath, keyfilePath, password, profile string, secretsConfig *SecretsConfig) (*EntryCreationResult, error)
	CreateSnapshot(dbPath, keyfilePath, password, profile string) (*SnapshotCreationResult, error)
	DeleteSnapshot(dbPath, keyfilePath, password, profile, version string) error
	ListSnapshots(dbPath, keyfilePath, password, profile string) ([]string, error)
}

// DefaultKeePassManager follows SRP - Single Responsibility for KeePass operations
type DefaultKeePassManager struct {
	logger Logger
}

// NewKeePassManager factory function follows DIP - Dependency Inversion Principle
func NewKeePassManager(logger Logger) KeePassManager {
	return &DefaultKeePassManager{
		logger: logger,
	}
}

// DatabaseExists checks if the KeePass database file exists
func (k *DefaultKeePassManager) DatabaseExists(dbPath string) bool {
	k.logger.Debug("Checking if database exists: " + dbPath)
	
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		k.logger.Debug("Database does not exist")
		return false
	}
	
	k.logger.Debug("Database already exists")
	return true
}

// KeyfileExists checks if the keyfile exists
func (k *DefaultKeePassManager) KeyfileExists(keyfilePath string) bool {
	k.logger.Debug("Checking if keyfile exists: " + keyfilePath)
	
	if _, err := os.Stat(keyfilePath); os.IsNotExist(err) {
		k.logger.Debug("Keyfile does not exist")
		return false
	}
	
	k.logger.Debug("Keyfile already exists")
	return true
}

// GenerateKeyfile creates a cryptographically secure keyfile
func (k *DefaultKeePassManager) GenerateKeyfile(keyfilePath string) error {
	k.logger.Debug("Generating secure keyfile: " + keyfilePath)
	
	// Generate 512 bytes of cryptographically secure random data (military-grade security)
	keyData := make([]byte, 512)
	if _, err := rand.Read(keyData); err != nil {
		return fmt.Errorf("failed to generate secure random data: %v", err)
	}
	
	// Ensure directory exists
	dir := filepath.Dir(keyfilePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create keyfile directory: %v", err)
	}
	
	// Write keyfile with restrictive permissions (read-only for owner)
	if err := os.WriteFile(keyfilePath, keyData, 0400); err != nil {
		return fmt.Errorf("failed to write keyfile: %v", err)
	}
	
	k.logger.Success("Generated secure keyfile: " + keyfilePath)
	return nil
}

// ValidatePaths ensures the database and keyfile paths are valid
func (k *DefaultKeePassManager) ValidatePaths(dbPath, keyfilePath string) error {
	k.logger.Debug("Validating paths")
	
	// Validate database path directory
	dbDir := filepath.Dir(dbPath)
	if err := k.validateDirectory(dbDir, "database"); err != nil {
		return err
	}
	
	// Validate keyfile path directory
	keyDir := filepath.Dir(keyfilePath)
	if err := k.validateDirectory(keyDir, "keyfile"); err != nil {
		return err
	}
	
	// Ensure paths are not the same
	if dbPath == keyfilePath {
		return fmt.Errorf("database and keyfile paths cannot be the same")
	}
	
	k.logger.Debug("Paths are valid")
	return nil
}

// validateDirectory ensures a directory exists and is writable
func (k *DefaultKeePassManager) validateDirectory(dirPath, pathType string) error {
	// Check if directory exists, create if it doesn't
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		k.logger.Debug("Creating " + pathType + " directory: " + dirPath)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return fmt.Errorf("failed to create %s directory: %v", pathType, err)
		}
	}
	
	// Test write permissions by creating and removing a temporary file
	tempFile := filepath.Join(dirPath, ".keepass_write_test")
	if err := os.WriteFile(tempFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("%s directory is not writable: %v", pathType, err)
	}
	
	if err := os.Remove(tempFile); err != nil {
		k.logger.Debug("Warning: failed to remove test file: " + err.Error())
	}
	
	return nil
}

// CreateDatabase creates a new KeePass database with keyfile and password
func (k *DefaultKeePassManager) CreateDatabase(dbPath, keyfilePath, password string) error {
	k.logger.Debug("Creating KeePass database: " + dbPath)
	
	// Validate inputs
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}
	
	// Ensure database directory exists
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return fmt.Errorf("failed to create database directory: %v", err)
	}
	
	// Create credentials with password and keyfile
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		return fmt.Errorf("failed to create credentials: %v", err)
	}
	
	// Create a new database
	db := gokeepasslib.NewDatabase()
	
	// Set credentials FIRST
	db.Credentials = credentials
	
	// Create the root group properly
	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "SECRETS YOHNAH"
	
	// Ensure the root group has proper metadata
	rootGroup.UUID = gokeepasslib.NewUUID()
	
	// Clear any existing groups and set our root group
	db.Content.Root.Groups = []gokeepasslib.Group{rootGroup}
	
	// Write database to file
	file, err := os.Create(dbPath)
	if err != nil {
		return fmt.Errorf("failed to create database file: %v", err)
	}
	defer file.Close()
	
	// Encode database
	encoder := gokeepasslib.NewEncoder(file)
	if err := encoder.Encode(db); err != nil {
		return fmt.Errorf("failed to encode database: %v", err)
	}
	
	k.logger.Success("Created KeePass database: " + dbPath)
	k.logger.Info("Database created with sample entry - remember to change the default password!")
	k.logger.Info("Use the generated keyfile and your password to access the database")
	return nil
}

// EnsureProfileStructure connects to the database and ensures the profile group structure exists
func (k *DefaultKeePassManager) EnsureProfileStructure(dbPath, keyfilePath, password, profile string) error {
	k.logger.Debug("Ensuring profile structure: " + profile)
	
	// Create credentials
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		return fmt.Errorf("failed to create credentials: %v", err)
	}
	
	// Open database
	file, err := os.Open(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}
	defer file.Close()
	
	// Decode database
	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials
	decoder := gokeepasslib.NewDecoder(file)
	if err := decoder.Decode(db); err != nil {
		return fmt.Errorf("failed to decode database: %v", err)
	}
	
	// Find SECRETS YOHNAH root group
	if len(db.Content.Root.Groups) == 0 {
		return fmt.Errorf("database has no root groups")
	}
	
	rootGroup := &db.Content.Root.Groups[0]
	if rootGroup.Name != "SECRETS YOHNAH" {
		return fmt.Errorf("expected root group 'SECRETS YOHNAH', found '%s'", rootGroup.Name)
	}
	
	// Check if profile group already exists
	var profileGroup *gokeepasslib.Group
	k.logger.Debug(fmt.Sprintf("Checking for existing profile '%s' among %d groups", profile, len(rootGroup.Groups)))
	for i := range rootGroup.Groups {
		k.logger.Debug(fmt.Sprintf("Checking group %d: '%s'", i, rootGroup.Groups[i].Name))
		if rootGroup.Groups[i].Name == profile {
			profileGroup = &rootGroup.Groups[i]
			k.logger.Debug("Profile group already exists: " + profile)
			break
		}
	}
	
	// Create profile group if it doesn't exist
	if profileGroup == nil {
		newProfileGroup := gokeepasslib.NewGroup()
		newProfileGroup.Name = profile
		newProfileGroup.UUID = gokeepasslib.NewUUID()
		
		rootGroup.Groups = append(rootGroup.Groups, newProfileGroup)
		profileGroup = &rootGroup.Groups[len(rootGroup.Groups)-1]
		k.logger.Success("Created profile group: " + profile)
	}
	
	// Check if HEAD group exists under profile
	var headGroup *gokeepasslib.Group
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == "HEAD" {
			headGroup = &profileGroup.Groups[i]
			k.logger.Debug("HEAD group already exists under profile: " + profile)
			break
		}
	}
	
	// Create HEAD group if it doesn't exist
	if headGroup == nil {
		newHeadGroup := gokeepasslib.NewGroup()
		newHeadGroup.Name = "HEAD"
		newHeadGroup.UUID = gokeepasslib.NewUUID()
		
		// Create version control entry in HEAD group
		versionEntry := gokeepasslib.NewEntry()
		versionEntry.UUID = gokeepasslib.NewUUID()
		versionEntry.Values = append(versionEntry.Values, gokeepasslib.ValueData{
			Key:   "Title",
			Value: gokeepasslib.V{Content: "version"},
		})
		versionEntry.Values = append(versionEntry.Values, gokeepasslib.ValueData{
			Key:   "UserName",
			Value: gokeepasslib.V{Content: ""},
		})
		versionEntry.Values = append(versionEntry.Values, gokeepasslib.ValueData{
			Key:   "Password",
			Value: gokeepasslib.V{Content: ""},
		})
		versionEntry.Values = append(versionEntry.Values, gokeepasslib.ValueData{
			Key:   "URL",
			Value: gokeepasslib.V{Content: ""},
		})
		versionEntry.Values = append(versionEntry.Values, gokeepasslib.ValueData{
			Key:   "Notes",
			Value: gokeepasslib.V{Content: "v1"},
		})
		
		// Add version entry to HEAD group
		newHeadGroup.Entries = append(newHeadGroup.Entries, versionEntry)
		
		profileGroup.Groups = append(profileGroup.Groups, newHeadGroup)
		headGroup = &profileGroup.Groups[len(profileGroup.Groups)-1]
		k.logger.Success("Created HEAD group under profile: " + profile)
		k.logger.Success("Created version control entry with v1")
	} else {
		// HEAD group exists, check if version entry exists
		var versionEntryExists bool
		for _, entry := range headGroup.Entries {
			for _, value := range entry.Values {
				if value.Key == "Title" && value.Value.Content == "version" {
					versionEntryExists = true
					k.logger.Debug("Version entry already exists in HEAD group")
					break
				}
			}
			if versionEntryExists {
				break
			}
		}
		
		// Create version entry if it doesn't exist
		if !versionEntryExists {
			versionEntry := gokeepasslib.NewEntry()
			versionEntry.UUID = gokeepasslib.NewUUID()
			versionEntry.Values = append(versionEntry.Values, gokeepasslib.ValueData{
				Key:   "Title",
				Value: gokeepasslib.V{Content: "version"},
			})
			versionEntry.Values = append(versionEntry.Values, gokeepasslib.ValueData{
				Key:   "UserName",
				Value: gokeepasslib.V{Content: ""},
			})
			versionEntry.Values = append(versionEntry.Values, gokeepasslib.ValueData{
				Key:   "Password",
				Value: gokeepasslib.V{Content: ""},
			})
			versionEntry.Values = append(versionEntry.Values, gokeepasslib.ValueData{
				Key:   "URL",
				Value: gokeepasslib.V{Content: ""},
			})
			versionEntry.Values = append(versionEntry.Values, gokeepasslib.ValueData{
				Key:   "Notes",
				Value: gokeepasslib.V{Content: "v1"},
			})
			
			// Add version entry to existing HEAD group
			headGroup.Entries = append(headGroup.Entries, versionEntry)
			k.logger.Success("Created version control entry with v1 in existing HEAD group")
		}
	}
	
	// Save the modified database
	outputFile, err := os.Create(dbPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()
	
	encoder := gokeepasslib.NewEncoder(outputFile)
	if err := encoder.Encode(db); err != nil {
		return fmt.Errorf("failed to save database: %v", err)
	}
	
	k.logger.Success("Profile structure ensured: " + profile + " -> HEAD")
	return nil
}

// CreateSnapshot creates a snapshot from the current HEAD group
func (k *DefaultKeePassManager) CreateSnapshot(dbPath, keyfilePath, password, profile string) (*SnapshotCreationResult, error) {
	k.logger.Debug("Creating snapshot for profile: " + profile)
	
	// Create credentials
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create credentials: %v", err)
	}
	
	// Open database
	file, err := os.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}
	defer file.Close()
	
	// Decode database
	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials
	decoder := gokeepasslib.NewDecoder(file)
	if err := decoder.Decode(db); err != nil {
		return nil, fmt.Errorf("failed to decode database: %v", err)
	}
	
	// Find root group
	if len(db.Content.Root.Groups) == 0 {
		return nil, fmt.Errorf("database has no root groups")
	}
	
	rootGroup := &db.Content.Root.Groups[0]
	if rootGroup.Name != "SECRETS YOHNAH" {
		return nil, fmt.Errorf("expected root group 'SECRETS YOHNAH', found '%s'", rootGroup.Name)
	}
	
	// Find profile group
	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profile {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}
	
	if profileGroup == nil {
		return nil, fmt.Errorf("profile group '%s' not found", profile)
	}
	
	// Find HEAD group
	var headGroup *gokeepasslib.Group
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == "HEAD" {
			headGroup = &profileGroup.Groups[i]
			break
		}
	}
	
	if headGroup == nil {
		return nil, fmt.Errorf("HEAD group not found under profile '%s'", profile)
	}
	
	// Get current version from HEAD
	currentVersion, err := k.getVersionFromGroup(headGroup)
	if err != nil {
		return nil, fmt.Errorf("failed to get current version from HEAD: %v", err)
	}
	
	k.logger.Debug("Current HEAD version: " + currentVersion)
	
	// Check if snapshot with this version already exists
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == currentVersion {
			return nil, fmt.Errorf("snapshot with version '%s' already exists", currentVersion)
		}
	}
	
	// Clone HEAD group to create snapshot
	snapshotGroup := k.cloneGroup(*headGroup)
	snapshotGroup.Name = currentVersion
	snapshotGroup.UUID = gokeepasslib.NewUUID()
	
	// Add snapshot to profile group
	profileGroup.Groups = append(profileGroup.Groups, snapshotGroup)
	k.logger.Success("Created snapshot: " + currentVersion)
	
	// Update HEAD version to next version
	nextVersion, err := k.getNextVersion(currentVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate next version: %v", err)
	}
	
	if err := k.updateVersionInGroup(headGroup, nextVersion); err != nil {
		return nil, fmt.Errorf("failed to update HEAD version: %v", err)
	}
	
	k.logger.Success("Updated HEAD version to: " + nextVersion)
	
	// Save the modified database
	if err := k.saveDatabase(db, dbPath); err != nil {
		return nil, fmt.Errorf("failed to save database: %v", err)
	}
	
	k.logger.Success("Snapshot created successfully: " + profile + " -> " + currentVersion)
	
	// Return snapshot creation result
	return &SnapshotCreationResult{
		CreatedVersion: currentVersion,
		NewHeadVersion: nextVersion,
	}, nil
}

// DeleteSnapshot deletes a specific snapshot version
func (k *DefaultKeePassManager) DeleteSnapshot(dbPath, keyfilePath, password, profile, version string) error {
	k.logger.Debug("Deleting snapshot: " + profile + " -> " + version)
	
	// Protect HEAD from deletion
	if version == "HEAD" {
		return fmt.Errorf("cannot delete HEAD group")
	}
	
	// Create credentials
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		return fmt.Errorf("failed to create credentials: %v", err)
	}
	
	// Open database
	file, err := os.Open(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}
	defer file.Close()
	
	// Decode database
	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials
	decoder := gokeepasslib.NewDecoder(file)
	if err := decoder.Decode(db); err != nil {
		return fmt.Errorf("failed to decode database: %v", err)
	}
	
	// Find root group
	if len(db.Content.Root.Groups) == 0 {
		return fmt.Errorf("database has no root groups")
	}
	
	rootGroup := &db.Content.Root.Groups[0]
	if rootGroup.Name != "SECRETS YOHNAH" {
		return fmt.Errorf("expected root group 'SECRETS YOHNAH', found '%s'", rootGroup.Name)
	}
	
	// Find profile group
	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profile {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}
	
	if profileGroup == nil {
		return fmt.Errorf("profile group '%s' not found", profile)
	}
	
	// Find and remove the snapshot group
	found := false
	for i := len(profileGroup.Groups) - 1; i >= 0; i-- {
		if profileGroup.Groups[i].Name == version {
			// Don't delete HEAD again for safety
			if version == "HEAD" {
				return fmt.Errorf("cannot delete HEAD group")
			}
			
			// Remove the group from slice
			profileGroup.Groups = append(profileGroup.Groups[:i], profileGroup.Groups[i+1:]...)
			found = true
			break
		}
	}
	
	if !found {
		return fmt.Errorf("snapshot version '%s' not found", version)
	}
	
	// Save the modified database
	if err := k.saveDatabase(db, dbPath); err != nil {
		return fmt.Errorf("failed to save database: %v", err)
	}
	
	k.logger.Success("Snapshot deleted successfully: " + profile + " -> " + version)
	return nil
}

// ListSnapshots lists all snapshot versions for a profile
func (k *DefaultKeePassManager) ListSnapshots(dbPath, keyfilePath, password, profile string) ([]string, error) {
	k.logger.Debug("Listing snapshots for profile: " + profile)
	
	// Create credentials
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create credentials: %v", err)
	}
	
	// Open database
	file, err := os.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}
	defer file.Close()
	
	// Decode database
	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials
	decoder := gokeepasslib.NewDecoder(file)
	if err := decoder.Decode(db); err != nil {
		return nil, fmt.Errorf("failed to decode database: %v", err)
	}
	
	// Find root group
	if len(db.Content.Root.Groups) == 0 {
		return nil, fmt.Errorf("database has no root groups")
	}
	
	rootGroup := &db.Content.Root.Groups[0]
	if rootGroup.Name != "SECRETS YOHNAH" {
		return nil, fmt.Errorf("expected root group 'SECRETS YOHNAH', found '%s'", rootGroup.Name)
	}
	
	// Find profile group
	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profile {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}
	
	if profileGroup == nil {
		return nil, fmt.Errorf("profile group '%s' not found", profile)
	}
	
	// Collect all snapshot versions
	var snapshots []string
	for _, group := range profileGroup.Groups {
		snapshots = append(snapshots, group.Name)
	}
	
	// Sort snapshots for consistent output
	sort.Strings(snapshots)
	
	k.logger.Debug(fmt.Sprintf("Found %d snapshots", len(snapshots)))
	return snapshots, nil
}

// getVersionFromGroup extracts version from the version entry in a group
func (k *DefaultKeePassManager) getVersionFromGroup(group *gokeepasslib.Group) (string, error) {
	for _, entry := range group.Entries {
		if entry.GetTitle() == "version" {
			return entry.GetContent("Notes"), nil
		}
	}
	return "", fmt.Errorf("version entry not found in group")
}

// updateVersionInGroup updates the version entry in a group
func (k *DefaultKeePassManager) updateVersionInGroup(group *gokeepasslib.Group, newVersion string) error {
	for i := range group.Entries {
		if group.Entries[i].GetTitle() == "version" {
			// Update the Notes field with the new version
			for j := range group.Entries[i].Values {
				if group.Entries[i].Values[j].Key == "Notes" {
					group.Entries[i].Values[j].Value.Content = newVersion
					return nil
				}
			}
			// If Notes field doesn't exist, add it
			group.Entries[i].Values = append(group.Entries[i].Values, gokeepasslib.ValueData{
				Key: "Notes",
				Value: gokeepasslib.V{Content: newVersion},
			})
			return nil
		}
	}
	return fmt.Errorf("version entry not found in group")
}

// getNextVersion calculates the next semantic version
func (k *DefaultKeePassManager) getNextVersion(currentVersion string) (string, error) {
	// Parse version like "v1" or "v1.0.0"
	if !strings.HasPrefix(currentVersion, "v") {
		return "", fmt.Errorf("invalid version format: %s", currentVersion)
	}
	
	versionPart := strings.TrimPrefix(currentVersion, "v")
	
	// Handle simple version format like "1" 
	if !strings.Contains(versionPart, ".") {
		// Parse major version and increment it
		major, err := strconv.Atoi(versionPart)
		if err != nil {
			return "", fmt.Errorf("invalid version: %s", versionPart)
		}
		return fmt.Sprintf("v%d", major+1), nil
	}
	
	// Handle semantic version format like "1.0.0"
	parts := strings.Split(versionPart, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid semantic version format: %s", currentVersion)
	}
	
	// Parse major version and increment it
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid major version: %s", parts[0])
	}
	
	// For simplicity, just increment major version
	return fmt.Sprintf("v%d.0.0", major+1), nil
}

// cloneGroup creates a deep copy of a group
func (k *DefaultKeePassManager) cloneGroup(original gokeepasslib.Group) gokeepasslib.Group {
	clone := gokeepasslib.Group{
		UUID:                    gokeepasslib.NewUUID(), // New UUID for clone
		Name:                    original.Name,
		Notes:                   original.Notes,
		IconID:                  original.IconID,
		Times:                   original.Times,
		IsExpanded:              original.IsExpanded,
		DefaultAutoTypeSequence: original.DefaultAutoTypeSequence,
		EnableAutoType:          original.EnableAutoType,
		EnableSearching:         original.EnableSearching,
		LastTopVisibleEntry:     original.LastTopVisibleEntry,
	}
	
	// Clone entries
	for _, entry := range original.Entries {
		clonedEntry := gokeepasslib.Entry{
			UUID:                    gokeepasslib.NewUUID(), // New UUID for clone
			IconID:                  entry.IconID,
			ForegroundColor:         entry.ForegroundColor,
			BackgroundColor:         entry.BackgroundColor,
			OverrideURL:             entry.OverrideURL,
			Tags:                    entry.Tags,
			Times:                   entry.Times,
		}
		
		// Clone values
		for _, value := range entry.Values {
			clonedEntry.Values = append(clonedEntry.Values, gokeepasslib.ValueData{
				Key:   value.Key,
				Value: gokeepasslib.V{Content: value.Value.Content, Protected: value.Value.Protected},
			})
		}
		
		clone.Entries = append(clone.Entries, clonedEntry)
	}
	
	// Clone subgroups recursively
	for _, subgroup := range original.Groups {
		clonedSubgroup := k.cloneGroup(subgroup)
		clone.Groups = append(clone.Groups, clonedSubgroup)
	}
	
	return clone
}

// saveDatabase saves a KeePass database to file
func (k *DefaultKeePassManager) saveDatabase(db *gokeepasslib.Database, dbPath string) error {
	// Lock the database to protect from corruption
	if err := db.LockProtectedEntries(); err != nil {
		return fmt.Errorf("failed to lock protected entries: %v", err)
	}
	
	// Create output file
	file, err := os.Create(dbPath)
	if err != nil {
		return fmt.Errorf("failed to create database file: %v", err)
	}
	defer file.Close()
	
	// Encode and write
	encoder := gokeepasslib.NewEncoder(file)
	if err := encoder.Encode(db); err != nil {
		return fmt.Errorf("failed to encode database: %v", err)
	}
	
	return nil
}

// CreateEnvironmentsAndEntries creates environments and entries based on secrets.yml
// ASSUMES the profile structure already exists - does NOT create profiles
func (k *DefaultKeePassManager) CreateEnvironmentsAndEntries(dbPath, keyfilePath, password, profile string, secretsConfig *SecretsConfig) (*EntryCreationResult, error) {
	k.logger.Debug("Creating environments and entries for profile: " + profile)
	
	result := &EntryCreationResult{
		CreatedEntries: 0,
		TotalEntries:   0,
	}
	
	// Create credentials
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create credentials: %v", err)
	}
	
	// Open database
	file, err := os.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}
	defer file.Close()
	
	// Decode database
	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials
	decoder := gokeepasslib.NewDecoder(file)
	if err := decoder.Decode(db); err != nil {
		return nil, fmt.Errorf("failed to decode database: %v", err)
	}
	
	// Find HEAD group (profile MUST already exist)
	headGroup, err := k.findHEADGroup(db, profile)
	if err != nil {
		return nil, fmt.Errorf("failed to find HEAD group (profile structure must be created first): %v", err)
	}
	
	// Create environments and entries
	for envName, items := range secretsConfig.Environments {
		k.logger.Debug("Creating environment: " + envName)
		
		// Find or create environment group
		envGroup := k.findOrCreateGroup(headGroup, envName)
		
		// Create entries for each item in the environment
		for _, item := range items {
			result.TotalEntries++
			created, err := k.createEntryFromItem(db, envGroup, item)
			if err != nil {
				return nil, fmt.Errorf("failed to create entry for item %s: %v", item.Name, err)
			}
			if created {
				result.CreatedEntries++
			}
		}
		
		k.logger.Success("Created environment: " + envName)
	}
	
	// Save the database
	if err := k.saveDatabase(db, dbPath); err != nil {
		return nil, fmt.Errorf("failed to save database: %v", err)
	}
	
	k.logger.Success("Environments and entries created successfully")
	return result, nil
}

// findHEADGroup finds the HEAD group within the specified profile
func (k *DefaultKeePassManager) findHEADGroup(db *gokeepasslib.Database, profile string) (*gokeepasslib.Group, error) {
	if len(db.Content.Root.Groups) == 0 {
		return nil, fmt.Errorf("database has no root groups")
	}
	
	rootGroup := &db.Content.Root.Groups[0]
	if rootGroup.Name != "SECRETS YOHNAH" {
		return nil, fmt.Errorf("expected root group 'SECRETS YOHNAH', found '%s'", rootGroup.Name)
	}
	
	// Find profile group
	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profile {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}
	
	if profileGroup == nil {
		return nil, fmt.Errorf("profile group '%s' not found", profile)
	}
	
	// Find HEAD group
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == "HEAD" {
			return &profileGroup.Groups[i], nil
		}
	}
	
	return nil, fmt.Errorf("HEAD group not found under profile '%s'", profile)
}

// findOrCreateGroup finds an existing group or creates a new one
func (k *DefaultKeePassManager) findOrCreateGroup(parentGroup *gokeepasslib.Group, groupName string) *gokeepasslib.Group {
	// Try to find existing group
	for i := range parentGroup.Groups {
		if parentGroup.Groups[i].Name == groupName {
			return &parentGroup.Groups[i]
		}
	}
	
	// Create new group
	newGroup := gokeepasslib.Group{
		UUID: gokeepasslib.NewUUID(),
		Name: groupName,
	}
	
	parentGroup.Groups = append(parentGroup.Groups, newGroup)
	return &parentGroup.Groups[len(parentGroup.Groups)-1]
}

// createEntryFromItem creates a KeePass entry from a secrets.yml item
// Returns true if a new entry was created, false if it already existed
func (k *DefaultKeePassManager) createEntryFromItem(db *gokeepasslib.Database, envGroup *gokeepasslib.Group, item EnvironmentItem) (bool, error) {
	k.logger.Debug("Creating entry for item: " + item.Name)
	
	// Parse entry path
	targetGroup, entryName := k.parseEntryPath(envGroup, item.Entry)
	
	// Check if entry already exists
	for _, entry := range targetGroup.Entries {
		if entry.GetTitle() == entryName {
			k.logger.Debug("Entry already exists: " + entryName)
			return false, nil
		}
	}
	
	// Create the entry
	entry := gokeepasslib.Entry{
		UUID: gokeepasslib.NewUUID(),
	}
	
	// Set standard KeePass fields first (required for compatibility)
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: entryName},
	})
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "UserName",
		Value: gokeepasslib.V{Content: ""},
	})
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Password",
		Value: gokeepasslib.V{Content: ""},
	})
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "URL",
		Value: gokeepasslib.V{Content: ""},
	})
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   "Notes",
		Value: gokeepasslib.V{Content: ""},
	})
	
	// Handle the field specified in the item
	if strings.HasPrefix(strings.ToLower(item.Key), "attachments/") {
		// Extract filename from "attachments/filename"
		filename := strings.TrimPrefix(item.Key, "attachments/")
		if strings.HasPrefix(strings.ToLower(item.Key), "Attachments/") {
			filename = strings.TrimPrefix(item.Key, "Attachments/")
		}
		
		// For text files, read the actual file content if it exists
		var textContent string
		
		// Try to read from common locations
		possiblePaths := []string{
			"/workspaces/secrets/.trash/" + filename,
			"/workspaces/secrets/" + filename,
			filename, // relative path
		}
		
		found := false
		for _, filePath := range possiblePaths {
			if fileData, err := os.ReadFile(filePath); err == nil {
				textContent = string(fileData)
				found = true
				k.logger.Debug("Read file content from: " + filePath)
				break
			}
		}
		
		// If file not found, use default text
		if !found {
			textContent = "To be completed by developer"
			k.logger.Debug("File not found, using default content for: " + filename)
		}
		
		// Create binary for plain text attachment (as KeePassXC does)
		binaryID := len(db.Content.Meta.Binaries) // Next available ID
		binary := gokeepasslib.Binary{
			ID:      binaryID,
			Content: []byte(textContent), // Plain text as bytes, no compression or encoding
		}

		// Add binary to database metadata
		db.Content.Meta.Binaries = append(db.Content.Meta.Binaries, binary)
		
		// Create binary reference in the entry
		binaryRef := gokeepasslib.NewBinaryReference(filename, binaryID)
		
		// Add the binary reference to the entry
		entry.Binaries = append(entry.Binaries, binaryRef)
		
		k.logger.Debug("Created plain text attachment: " + filename + " (ID: " + fmt.Sprintf("%d", binaryID) + ") for entry: " + entryName)
	} else {
		// Regular field
		fieldName, fieldValue := k.getFieldNameAndValue(item.Key)
		entry.Values = append(entry.Values, gokeepasslib.ValueData{
			Key:   fieldName,
			Value: gokeepasslib.V{Content: fieldValue},
		})
	}
	
	// Add entry to target group
	targetGroup.Entries = append(targetGroup.Entries, entry)
	
	k.logger.Success("Created entry: " + entryName)
	return true, nil
}

// parseEntryPath parses the entry path and creates necessary groups
func (k *DefaultKeePassManager) parseEntryPath(envGroup *gokeepasslib.Group, entryPath string) (*gokeepasslib.Group, string) {
	// Remove leading slash if present
	if strings.HasPrefix(entryPath, "/") {
		entryPath = strings.TrimPrefix(entryPath, "/")
	}
	
	// Split path into parts
	parts := strings.Split(entryPath, "/")
	entryName := parts[len(parts)-1]
	
	// If only entry name, return environment group
	if len(parts) == 1 {
		return envGroup, entryName
	}
	
	// Create intermediate groups
	currentGroup := envGroup
	for i := 0; i < len(parts)-1; i++ {
		currentGroup = k.findOrCreateGroup(currentGroup, parts[i])
	}
	
	return currentGroup, entryName
}

// getFieldNameAndValue returns the correct field name and default value
func (k *DefaultKeePassManager) getFieldNameAndValue(key string) (string, string) {
	// Check if it's an attachment
	if strings.HasPrefix(strings.ToLower(key), "attachments/") {
		// Extract the filename from "attachments/filename"
		filename := strings.TrimPrefix(key, "attachments/")
		if strings.HasPrefix(strings.ToLower(key), "attachments/") && !strings.HasPrefix(strings.ToLower(key), "Attachments/") {
			filename = strings.TrimPrefix(key, "attachments/")
		} else {
			filename = strings.TrimPrefix(key, "Attachments/")
		}
		
		// For attachments, we create a custom field with the filename
		// In KeePass, attachments are typically stored differently, but for now
		// we'll create a field indicating it's an attachment reference
		return filename, "To be completed by developer - attachment file"
	}
	
	// Check if it's a standard field (case-insensitive)
	if standardField, exists := standardFields[strings.ToLower(key)]; exists {
		return standardField, "To be completed by developer"
	}
	
	// Custom field - use as-is
	return key, "To be completed by developer"
}