package keepass

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/Yohnah/secrets/internal/logger"
)

// Manager interface follows ISP - Interface Segregation Principle
// Separates KeePass database operations
type Manager interface {
	CreateDatabase(dbPath, keyfilePath, password string) error
	DatabaseExists(dbPath, keyfilePath, password string) bool
}

// DefaultManager implements Manager interface
// Follows SRP - Single Responsibility Principle: only handles KeePass operations
type DefaultManager struct {
	logger logger.Logger
}

// NewManager creates a new KeePass manager
// Follows DIP - Dependency Inversion Principle: depends on Logger abstraction
func NewManager(logger logger.Logger) Manager {
	return &DefaultManager{
		logger: logger,
	}
}

// CreateDatabase creates a new KeePass database with password and keyfile
// Follows SRP - Single Responsibility Principle: only handles database creation
func (k *DefaultManager) CreateDatabase(dbPath, keyfilePath, password string) error {
	k.logger.Debug("Creating KeePass database: " + dbPath)
	k.logger.Debug("With keyfile: " + keyfilePath)

	// Create keyfile first
	if err := k.createKeyfile(keyfilePath); err != nil {
		return fmt.Errorf("failed to create keyfile: %v", err)
	}

	// Create credentials with password and keyfile
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		return fmt.Errorf("failed to create credentials: %v", err)
	}

	// Create new database
	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials

	// Create the database structure
	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Database"
	db.Content.Root = &gokeepasslib.RootData{Groups: []gokeepasslib.Group{rootGroup}}

	// Create directory if it doesn't exist
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create database directory: %v", err)
	}

	// Save the database
	file, err := os.Create(dbPath)
	if err != nil {
		return fmt.Errorf("failed to create database file: %v", err)
	}
	defer file.Close()

	encoder := gokeepasslib.NewEncoder(file)
	if err := encoder.Encode(db); err != nil {
		return fmt.Errorf("failed to encode database: %v", err)
	}

	k.logger.Debug("KeePass database created successfully")
	return nil
}

// DatabaseExists checks if a KeePass database exists and is valid
// Follows SRP - Single Responsibility Principle: only handles database validation
func (k *DefaultManager) DatabaseExists(dbPath, keyfilePath, password string) bool {
	k.logger.Debug("Checking if database exists: " + dbPath)

	// Check if file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		k.logger.Debug("Database file does not exist")
		return false
	}

	// Try to open and validate the database
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		k.logger.Debug("Failed to create credentials for validation")
		return false
	}

	file, err := os.Open(dbPath)
	if err != nil {
		k.logger.Debug("Failed to open database file")
		return false
	}
	defer file.Close()

	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials
	decoder := gokeepasslib.NewDecoder(file)
	if err := decoder.Decode(db); err != nil {
		k.logger.Debug("Failed to decode database: " + err.Error())
		return false
	}

	k.logger.Debug("Database exists and is valid")
	return true
}

// createKeyfile creates a cryptographically secure keyfile
// Follows SRP - Single Responsibility Principle: only handles keyfile creation
func (k *DefaultManager) createKeyfile(keyfilePath string) error {
	k.logger.Debug("Creating keyfile: " + keyfilePath)

	// Generate random keyfile data (64 bytes for strong security)
	keyData := make([]byte, 64)
	
	// Use crypto/rand for cryptographically secure random bytes
	if _, err := rand.Read(keyData); err != nil {
		return fmt.Errorf("failed to generate secure random data: %v", err)
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(keyfilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create keyfile directory: %v", err)
	}

	// Write keyfile with restricted permissions
	if err := os.WriteFile(keyfilePath, keyData, 0600); err != nil {
		return fmt.Errorf("failed to write keyfile: %v", err)
	}

	k.logger.Debug("Keyfile created successfully")
	return nil
}