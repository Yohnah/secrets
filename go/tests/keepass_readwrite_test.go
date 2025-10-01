package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/Yohnah/secrets/internal/cli"
)

// TestKeePassReadWrite tests that we can create and read a KeePass database
func TestKeePassReadWrite(t *testing.T) {
	tempDir := t.TempDir()
	logger := cli.NewLogger(true)
	keepassManager := cli.NewKeePassManager(logger)
	
	dbPath := filepath.Join(tempDir, "test.kdbx")
	keyfilePath := filepath.Join(tempDir, "test.keyfile")
	password := "testpassword123"
	
	// Generate keyfile
	err := keepassManager.GenerateKeyfile(keyfilePath)
	if err != nil {
		t.Fatalf("Failed to generate keyfile: %v", err)
	}
	
	// Create database
	err = keepassManager.CreateDatabase(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	
	// Now try to read the database back
	t.Run("ReadCreatedDatabase", func(t *testing.T) {
		// Create credentials for reading
		credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
		if err != nil {
			t.Fatalf("Failed to create credentials for reading: %v", err)
		}
		
		// Open and read the created database
		db := gokeepasslib.NewDatabase()
		
		// Set credentials FIRST (same as used during creation)
		db.Credentials = credentials
		
		// Open file
		file, err := os.Open(dbPath)
		if err != nil {
			t.Fatalf("Failed to open database file: %v", err)
		}
		defer file.Close()
		
		// Create decoder and decode
		decoder := gokeepasslib.NewDecoder(file)
		err = decoder.Decode(db)
		if err != nil {
			t.Fatalf("Failed to decode database: %v", err)
		}
		
		// Unlock protected entries
		err = db.UnlockProtectedEntries()
		if err != nil {
			t.Fatalf("Failed to unlock database: %v", err)
		}
		
		// Verify we can access the content
		if len(db.Content.Root.Groups) == 0 {
			t.Error("Database should have at least one group")
		}
		
		// Verify the root group structure
		rootGroup := db.Content.Root.Groups[0]
		if rootGroup.Name != "SECRETS YOHNAH" {
			t.Errorf("Expected root group name 'SECRETS YOHNAH', got '%s'", rootGroup.Name)
		}
		
		t.Logf("Successfully read database with root group: %s", rootGroup.Name)
		t.Logf("Database structure is valid and accessible")
	})
}