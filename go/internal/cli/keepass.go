package cli

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tobischo/gokeepasslib/v3"
)

// KeePassManager interface follows ISP - Interface Segregation Principle
type KeePassManager interface {
	CreateDatabase(dbPath, keyfilePath, password string) error
	DatabaseExists(dbPath string) bool
	KeyfileExists(keyfilePath string) bool
	GenerateKeyfile(keyfilePath string) error
	ValidatePaths(dbPath, keyfilePath string) error
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