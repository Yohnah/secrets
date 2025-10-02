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
	Create(dbPath, keyfilePath, password string) error
	Exists(dbPath string) bool
	GenerateKeyfile(keyfilePath string) error
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

	// Create database with password and keyfile path
	db := gokeepasslib.NewDatabase()
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		return fmt.Errorf("failed to create credentials: %w", err)
	}
	db.Credentials = credentials // Create root group "SECRETS YOHNAH"
	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "SECRETS YOHNAH"
	db.Content.Root.Groups = append(db.Content.Root.Groups, rootGroup)

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
