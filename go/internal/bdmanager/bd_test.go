package bdmanager

import (
	"testing"

	"github.com/Yohnah/secrets/internal/loggermanager"
	"github.com/Yohnah/secrets/internal/validatormanager"
)

func TestNewStandardBD(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	validator := validatormanager.NewStandardValidator(logger)

	bd := NewStandardBD(logger, validator)

	if bd == nil {
		t.Error("Expected non-nil BD manager")
	}
}

func TestStandardBD_DatabaseExists(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	validator := validatormanager.NewStandardValidator(logger)
	bd := NewStandardBD(logger, validator)

	// Test with non-existent file
	exists := bd.DatabaseExists("/tmp/nonexistent-db.kdbx")
	if exists {
		t.Error("Expected false for non-existent database")
	}
}

func TestStandardBD_GenerateKeyfile(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	validator := validatormanager.NewStandardValidator(logger)
	bd := NewStandardBD(logger, validator)

	keyfilePath := t.TempDir() + "/test.key"

	err := bd.GenerateKeyfile(keyfilePath)
	if err != nil {
		t.Errorf("Failed to generate keyfile: %v", err)
	}

	// Verify keyfile exists
	exists := bd.DatabaseExists(keyfilePath)
	if !exists {
		t.Error("Keyfile was not created")
	}
}

func TestStandardBD_CreateAndDeleteDatabase(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	validator := validatormanager.NewStandardValidator(logger)
	bd := NewStandardBD(logger, validator)

	dbPath := t.TempDir() + "/test.kdbx"
	password := "123456"

	// Create database without keyfile
	err := bd.CreateDatabase(dbPath, password, "", "test")
	if err != nil {
		t.Errorf("Failed to create database: %v", err)
	}

	// Verify database exists
	if !bd.DatabaseExists(dbPath) {
		t.Error("Database was not created")
	}

	// Delete database
	err = bd.DeleteDatabase(dbPath)
	if err != nil {
		t.Errorf("Failed to delete database: %v", err)
	}

	// Verify database no longer exists
	if bd.DatabaseExists(dbPath) {
		t.Error("Database still exists after deletion")
	}
}

func TestStandardBD_CreateDatabaseWithKeyfile(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	validator := validatormanager.NewStandardValidator(logger)
	bd := NewStandardBD(logger, validator)

	dbPath := t.TempDir() + "/test-with-key.kdbx"
	keyfilePath := t.TempDir() + "/test.key"
	password := "123456"

	// Generate keyfile
	err := bd.GenerateKeyfile(keyfilePath)
	if err != nil {
		t.Fatalf("Failed to generate keyfile: %v", err)
	}

	// Create database with keyfile
	err = bd.CreateDatabase(dbPath, password, keyfilePath, "test")
	if err != nil {
		t.Errorf("Failed to create database with keyfile: %v", err)
	}

	// Verify database exists
	if !bd.DatabaseExists(dbPath) {
		t.Error("Database was not created")
	}
}
