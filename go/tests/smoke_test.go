package keepass_test

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Yohnah/secrets/internal/keepass"
)

// TestSimpleSmoke runs a basic smoke test to verify CRUD operations
func TestSimpleSmoke(t *testing.T) {
	// Ensure .trash directory exists
	trashDir := "/workspaces/secrets/.trash"
	if err := os.MkdirAll(trashDir, 0755); err != nil {
		t.Fatalf("Failed to create trash directory: %v", err)
	}

	// Create database in .trash
	timestamp := time.Now().Format("20060102_150405")
	dbPath := filepath.Join(trashDir, fmt.Sprintf("smoke_test_%s.kdbx", timestamp))
	
	// Generate random password (NEVER use predictable passwords!)
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		t.Fatalf("Failed to generate random password: %v", err)
	}
	password := hex.EncodeToString(randomBytes)
	
	t.Logf("=== SMOKE TEST ===")
	t.Logf("Database: %s", dbPath)
	t.Logf("Password: [GENERATED RANDOMLY - 32 chars]")
	
	// Create and test basic operations
	kp, err := keepass.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create KeePass instance: %v", err)
	}

	// Create database
	if err := kp.CreateDB("smokeuser", password, true); err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	// Get the keyfile path that was generated
	keyfilePath := kp.GetKeyFilePath()
	
	// Open database with the correct keyfile
	if err := kp.Open("smokeuser", password, keyfilePath); err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	// Test basic CRUD operations
	testPath := "/Test/Smoke/Example"
	operations := map[string]int{"create": 0, "read": 0, "update": 0, "delete": 0}
	
	// CREATE
	if err := kp.Write(testPath, "username", "smokeuser", false); err != nil {
		t.Errorf("Failed to write username: %v", err)
	} else {
		operations["create"]++
	}
	
	// Generate random test password content
	testPasswordBytes := make([]byte, 8)
	if _, err := rand.Read(testPasswordBytes); err != nil {
		t.Fatalf("Failed to generate test password content: %v", err)
	}
	testPasswordContent := hex.EncodeToString(testPasswordBytes)
	
	if err := kp.Write(testPath, "password", testPasswordContent, false); err != nil {
		t.Errorf("Failed to write password: %v", err)
	} else {
		operations["create"]++
	}
	if err := kp.Write(testPath, "email", "smoke@test.com", false); err != nil {
		t.Errorf("Failed to write email: %v", err)
	} else {
		operations["create"]++
	}
	if err := kp.Write(testPath, "config.json", `{"test": true}`, true); err != nil {
		t.Errorf("Failed to write attachment: %v", err)
	} else {
		operations["create"]++
	}
	
	// READ
	_, err = kp.Get(testPath, nil, nil)
	if err != nil {
		t.Errorf("Failed to get entire entry: %v", err)
	} else {
		operations["read"]++
	}
	
	field := "username"
	_, err = kp.Get(testPath, &field, nil)
	if err != nil {
		t.Errorf("Failed to get username field: %v", err)
	} else {
		operations["read"]++
	}
	
	// UPDATE
	if err := kp.Write(testPath, "username", "updated_smokeuser", false); err != nil {
		t.Errorf("Failed to update username: %v", err)
	} else {
		operations["update"]++
	}
	if err := kp.Write(testPath, "new_field", "new_value", false); err != nil {
		t.Errorf("Failed to add new field: %v", err)
	} else {
		operations["update"]++
	}
	
	// LIST
	entries, err := kp.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	operations["read"]++
	
	// DELETE field
	fieldToDelete := "email"
	if err := kp.Delete(testPath, &fieldToDelete); err != nil {
		t.Errorf("Failed to delete field: %v", err)
	} else {
		operations["delete"]++
	}
	
	// Verify field was deleted
	_, err = kp.Get(testPath, &fieldToDelete, nil)
	if err == nil {
		t.Errorf("Field should have been deleted but still exists")
	} else {
		operations["read"]++
	}
	
	// DELETE entry
	if err := kp.Delete(testPath, nil); err != nil {
		t.Errorf("Failed to delete entry: %v", err)
	} else {
		operations["delete"]++
	}
	
	// Verify entry was deleted
	_, err = kp.Get(testPath, nil, nil)
	if err == nil {
		t.Errorf("Entry should have been deleted but still exists")
	} else {
		operations["read"]++
	}
	
	// Close database
	kp.Close()
	
	// Summary
	t.Log("\n=== SMOKE TEST SUMMARY ===")
	t.Logf("CREATED: %d fields/attachments", operations["create"])
	t.Logf("READ: %d operations", operations["read"])
	t.Logf("UPDATE: %d fields", operations["update"])
	t.Logf("DELETE: %d operations", operations["delete"])
	t.Logf("LIST: %d entries found", len(entries))
}