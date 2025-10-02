package keepass_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/keepass"
)

func TestDatabaseManager_Create_Success(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "keepass_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.kdbx")
	keyfilePath := filepath.Join(tempDir, "test.keyfile")
	password := "test_password_123"

	dbMgr := keepass.NewDatabaseManager()

	err = dbMgr.Create(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify database file was created
	if !dbMgr.Exists(dbPath) {
		t.Error("Expected database file to exist")
	}

	// Verify keyfile was created
	if _, err := os.Stat(keyfilePath); os.IsNotExist(err) {
		t.Error("Expected keyfile to exist")
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

	// Verify keyfile size (should be 64 bytes for military-grade security)
	if info.Size() != 64 {
		t.Errorf("Expected keyfile size 64 bytes, got %d", info.Size())
	}
}

func TestDatabaseManager_Create_InvalidPath(t *testing.T) {
	dbMgr := keepass.NewDatabaseManager()

	// Test with invalid path (non-existent directory)
	err := dbMgr.Create("/nonexistent/directory/test.kdbx", "/nonexistent/directory/test.keyfile", "password")
	if err == nil {
		t.Error("Expected error for invalid path, got nil")
	}
}

func TestDatabaseManager_Create_EmptyPassword(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "keepass_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.kdbx")
	keyfilePath := filepath.Join(tempDir, "test.keyfile")

	dbMgr := keepass.NewDatabaseManager()

	err = dbMgr.Create(dbPath, keyfilePath, "")
	if err == nil {
		t.Error("Expected error for empty password, got nil")
	}
}

func TestDatabaseManager_Exists(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "keepass_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.kdbx")
	nonexistentPath := filepath.Join(tempDir, "nonexistent.kdbx")

	dbMgr := keepass.NewDatabaseManager()

	// Test non-existent file
	if dbMgr.Exists(nonexistentPath) {
		t.Error("Expected false for non-existent file, got true")
	}

	// Create a file and test
	err = ioutil.WriteFile(dbPath, []byte("dummy content"), 0600)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	if !dbMgr.Exists(dbPath) {
		t.Error("Expected true for existing file, got false")
	}
}

func TestDatabaseManager_GenerateKeyfile(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "keepass_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	keyfilePath := filepath.Join(tempDir, "test.keyfile")

	dbMgr := keepass.NewDatabaseManager()

	err = dbMgr.GenerateKeyfile(keyfilePath)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(keyfilePath); os.IsNotExist(err) {
		t.Error("Expected keyfile to exist")
	}

	// Verify file size
	info, err := os.Stat(keyfilePath)
	if err != nil {
		t.Fatalf("Failed to stat keyfile: %v", err)
	}

	if info.Size() != 64 {
		t.Errorf("Expected keyfile size 64 bytes, got %d", info.Size())
	}

	// Verify file permissions
	expectedPerm := os.FileMode(0600)
	if info.Mode().Perm() != expectedPerm {
		t.Errorf("Expected keyfile permissions %v, got %v", expectedPerm, info.Mode().Perm())
	}

	// Verify file content is random (two generations should be different)
	keyfilePath2 := filepath.Join(tempDir, "test2.keyfile")
	err = dbMgr.GenerateKeyfile(keyfilePath2)
	if err != nil {
		t.Fatalf("Expected no error for second keyfile, got %v", err)
	}

	content1, err := ioutil.ReadFile(keyfilePath)
	if err != nil {
		t.Fatalf("Failed to read first keyfile: %v", err)
	}

	content2, err := ioutil.ReadFile(keyfilePath2)
	if err != nil {
		t.Fatalf("Failed to read second keyfile: %v", err)
	}

	// Compare content (should be different for cryptographically secure generation)
	if string(content1) == string(content2) {
		t.Error("Expected different keyfile content for two generations, got identical")
	}
}

func TestDatabaseManager_GenerateKeyfile_InvalidPath(t *testing.T) {
	dbMgr := keepass.NewDatabaseManager()

	err := dbMgr.GenerateKeyfile("/nonexistent/directory/test.keyfile")
	if err == nil {
		t.Error("Expected error for invalid path, got nil")
	}
}
