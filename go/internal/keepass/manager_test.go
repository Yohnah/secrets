package keepass

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/logger"
)

func TestDefaultManager(t *testing.T) {
	log := logger.New(false)
	manager := NewManager(log)
	
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "keepass_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	dbPath := filepath.Join(tmpDir, "test.kdbx")
	keyfilePath := filepath.Join(tmpDir, "test.keyfile")
	password := "123456"
	
	t.Run("CreateDatabase", func(t *testing.T) {
		err := manager.CreateDatabase(dbPath, keyfilePath, password)
		if err != nil {
			t.Fatalf("CreateDatabase failed: %v", err)
		}
		
		// Verify database file exists
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			t.Error("Database file was not created")
		}
		
		// Verify keyfile exists
		if _, err := os.Stat(keyfilePath); os.IsNotExist(err) {
			t.Error("Keyfile was not created")
		}
		
		// Verify keyfile has correct permissions
		info, err := os.Stat(keyfilePath)
		if err != nil {
			t.Fatalf("Failed to stat keyfile: %v", err)
		}
		
		expectedPerm := os.FileMode(0600)
		if info.Mode().Perm() != expectedPerm {
			t.Errorf("Expected keyfile permissions %v, got %v", expectedPerm, info.Mode().Perm())
		}
	})
	
	t.Run("DatabaseExists", func(t *testing.T) {
		// Should return true for valid database
		if !manager.DatabaseExists(dbPath, keyfilePath, password) {
			t.Error("DatabaseExists should return true for valid database")
		}
		
		// Should return false for non-existent database
		nonExistentPath := filepath.Join(tmpDir, "nonexistent.kdbx")
		if manager.DatabaseExists(nonExistentPath, keyfilePath, password) {
			t.Error("DatabaseExists should return false for non-existent database")
		}
		
		// Should return false for wrong password
		if manager.DatabaseExists(dbPath, keyfilePath, "wrongpassword") {
			t.Error("DatabaseExists should return false for wrong password")
		}
	})
	
	t.Run("ManagerInterface", func(t *testing.T) {
		// Test that our manager implements the Manager interface
		var mgr Manager = NewManager(log)
		
		// This should compile without issues
		_ = mgr.CreateDatabase(dbPath+"2", keyfilePath+"2", password)
		_ = mgr.DatabaseExists(dbPath, keyfilePath, password)
	})
}