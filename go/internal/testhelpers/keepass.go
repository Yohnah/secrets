package testhelpers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/keepass"
)

// TestDatabase holds test database configuration
type TestDatabase struct {
	DBPath      string
	KeyfilePath string
	Password    string
	TempDir     string
	Manager     keepass.Manager
}

// SetupTestDatabase creates a temporary test database with all necessary files
// Returns a TestDatabase struct and a cleanup function
func SetupTestDatabase(t *testing.T, rootGroupName string) (*TestDatabase, func()) {
	t.Helper()

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "keepass_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Setup paths
	dbPath := filepath.Join(tempDir, "test.kdbx")
	keyfilePath := filepath.Join(tempDir, "test.key")
	password := "testpassword"

	// Create manager
	kpMgr := keepass.NewManager()

	// Generate keyfile
	err = kpMgr.GenerateKeyfile(keyfilePath)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to generate keyfile: %v", err)
	}

	// Create database
	err = kpMgr.CreateDatabase(dbPath, keyfilePath, password, rootGroupName)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create database: %v", err)
	}

	testDB := &TestDatabase{
		DBPath:      dbPath,
		KeyfilePath: keyfilePath,
		Password:    password,
		TempDir:     tempDir,
		Manager:     kpMgr,
	}

	cleanup := func() {
		os.RemoveAll(tempDir)
	}

	return testDB, cleanup
}

// OpenTestSession opens a database session for testing
// Returns the manager and a cleanup function that saves and closes the session
func OpenTestSession(t *testing.T, dbPath, keyfilePath, password string) (keepass.Manager, func()) {
	t.Helper()

	kpMgr := keepass.NewManager()

	err := kpMgr.Open(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	cleanup := func() {
		if err := kpMgr.SaveAndClose(); err != nil {
			t.Errorf("Failed to save and close database: %v", err)
		}
	}

	return kpMgr, cleanup
}

// SetupTestDatabaseWithSession creates a test database and opens a session
// Returns the TestDatabase and a cleanup function that closes session and removes files
func SetupTestDatabaseWithSession(t *testing.T, rootGroupName string) (*TestDatabase, func()) {
	t.Helper()

	testDB, cleanupDB := SetupTestDatabase(t, rootGroupName)

	// Open session
	err := testDB.Manager.Open(testDB.DBPath, testDB.KeyfilePath, testDB.Password)
	if err != nil {
		cleanupDB()
		t.Fatalf("Failed to open database session: %v", err)
	}

	cleanup := func() {
		if testDB.Manager.IsOpen() {
			if err := testDB.Manager.SaveAndClose(); err != nil {
				t.Errorf("Failed to save and close database: %v", err)
			}
		}
		cleanupDB()
	}

	return testDB, cleanup
}

// CreateTestProfile creates a profile with environment in the database
// Assumes the database session is already open
func CreateTestProfile(t *testing.T, mgr keepass.Manager, profileName, envName string) {
	t.Helper()

	err := mgr.CreateProfile(profileName)
	if err != nil {
		t.Fatalf("Failed to create profile '%s': %v", profileName, err)
	}

	err = mgr.CreateGroup(profileName, "HEAD", envName)
	if err != nil {
		t.Fatalf("Failed to create environment '%s': %v", envName, err)
	}
}
