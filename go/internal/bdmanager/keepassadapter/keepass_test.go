package keepassadapter

import (
	"os"
	"testing"

	"github.com/Yohnah/secrets/internal/loggermanager"
)

func TestNewKeePassAdapter(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	adapter := NewKeePassAdapter(logger)

	if adapter == nil {
		t.Error("Expected non-nil KeePass adapter")
	}
}

func TestStandardKeePassAdapter_DatabaseExists(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	adapter := NewKeePassAdapter(logger)

	// Test with non-existent file
	exists := adapter.DatabaseExists("/tmp/nonexistent.kdbx")
	if exists {
		t.Error("Expected false for non-existent database")
	}

	// Test with existing file
	testFile := t.TempDir() + "/existing.txt"
	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	exists = adapter.DatabaseExists(testFile)
	if !exists {
		t.Error("Expected true for existing file")
	}
}

func TestStandardKeePassAdapter_GenerateKeyfile(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	adapter := NewKeePassAdapter(logger)

	keyfilePath := t.TempDir() + "/test.key"

	err := adapter.GenerateKeyfile(keyfilePath)
	if err != nil {
		t.Errorf("Failed to generate keyfile: %v", err)
	}

	// Verify keyfile exists and has correct size (64 bytes)
	data, err := os.ReadFile(keyfilePath)
	if err != nil {
		t.Errorf("Keyfile not created: %v", err)
	}
	if len(data) != 64 {
		t.Errorf("Expected keyfile size 64 bytes, got %d", len(data))
	}

	// Verify file permissions
	info, err := os.Stat(keyfilePath)
	if err != nil {
		t.Fatalf("Failed to stat keyfile: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("Expected permissions 0600, got %o", info.Mode().Perm())
	}
}

func TestStandardKeePassAdapter_CreateDatabase(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	adapter := NewKeePassAdapter(logger)

	dbPath := t.TempDir() + "/test.kdbx"
	password := "123456"

	err := adapter.CreateDatabase(dbPath, password, "", "test")
	if err != nil {
		t.Errorf("Failed to create database: %v", err)
	}

	// Verify database file exists
	if !adapter.DatabaseExists(dbPath) {
		t.Error("Database file was not created")
	}

	// Verify file is not empty
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("Failed to stat database: %v", err)
	}
	if info.Size() == 0 {
		t.Error("Database file is empty")
	}
}

func TestStandardKeePassAdapter_CreateDatabase_EmptyPassword(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	adapter := NewKeePassAdapter(logger)

	dbPath := t.TempDir() + "/test-empty-pass.kdbx"

	err := adapter.CreateDatabase(dbPath, "", "", "test")
	if err == nil {
		t.Error("Expected error for empty password")
	}
}

func TestStandardKeePassAdapter_CreateDatabase_WithKeyfile(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	adapter := NewKeePassAdapter(logger)

	dbPath := t.TempDir() + "/test-with-key.kdbx"
	keyfilePath := t.TempDir() + "/test.key"
	password := "123456"

	// Generate keyfile first
	err := adapter.GenerateKeyfile(keyfilePath)
	if err != nil {
		t.Fatalf("Failed to generate keyfile: %v", err)
	}

	// Create database with keyfile
	err = adapter.CreateDatabase(dbPath, password, keyfilePath, "production")
	if err != nil {
		t.Errorf("Failed to create database with keyfile: %v", err)
	}

	// Verify database exists
	if !adapter.DatabaseExists(dbPath) {
		t.Error("Database was not created")
	}
}

func TestStandardKeePassAdapter_CreateDatabase_InvalidKeyfile(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	adapter := NewKeePassAdapter(logger)

	dbPath := t.TempDir() + "/test-invalid-key.kdbx"
	keyfilePath := "/tmp/nonexistent-keyfile.key"
	password := "123456"

	err := adapter.CreateDatabase(dbPath, password, keyfilePath, "test")
	if err == nil {
		t.Error("Expected error for non-existent keyfile")
	}
}

func TestStandardKeePassAdapter_DeleteDatabase(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	adapter := NewKeePassAdapter(logger)

	// Create a test file to delete
	dbPath := t.TempDir() + "/to-delete.kdbx"
	if err := os.WriteFile(dbPath, []byte("test"), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Verify file exists
	if !adapter.DatabaseExists(dbPath) {
		t.Fatal("Test file was not created")
	}

	// Delete the file
	err := adapter.DeleteDatabase(dbPath)
	if err != nil {
		t.Errorf("Failed to delete database: %v", err)
	}

	// Verify file no longer exists
	if adapter.DatabaseExists(dbPath) {
		t.Error("Database still exists after deletion")
	}
}

func TestStandardKeePassAdapter_DeleteDatabase_NonExistent(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	adapter := NewKeePassAdapter(logger)

	err := adapter.DeleteDatabase("/tmp/nonexistent-to-delete.kdbx")
	if err == nil {
		t.Error("Expected error when deleting non-existent file")
	}
}
