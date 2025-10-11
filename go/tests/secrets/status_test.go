package secrets_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/output"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/Yohnah/secrets/internal/types"
	"github.com/Yohnah/secrets/internal/validator"
	"github.com/tobischo/gokeepasslib/v3"
)

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// TestStatus_WithValidDatabase tests status command with accessible database
func TestStatus_WithValidDatabase(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Setup mock KeePass manager
	mockKP := newMockKeePassManager()
	// Configure mock for valid database with proper structure
	mockKP.db = &gokeepasslib.Database{
		Content: &gokeepasslib.DBContent{
			Root: &gokeepasslib.RootData{
				Groups: []gokeepasslib.Group{
					{Name: "Root", Groups: []gokeepasslib.Group{}},
				},
			},
		},
	}

	// Setup managers
	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, &types.CommandFlags{}, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKP, output.NewManager(), validator.NewManager())

	// Setup infrastructure first
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Initialize first
	err = secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Run status
	err = secretsMgr.Status()
	if err != nil {
		t.Errorf("Status failed with valid database: %v", err)
	}
}

// TestStatus_WithoutDatabase tests status command when database doesn't exist
func TestStatus_WithoutDatabase(t *testing.T) {
	tmpDir := setupTestDir(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Setup mock KeePass manager
	mockKP := newMockKeePassManager()
	// Configure mock for non-existent database
	mockKP.openError = &testError{msg: "database not found"}

	// Setup managers without initializing
	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, &types.CommandFlags{}, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKP, output.NewManager(), validator.NewManager())

	// Run status without initializing first
	err := secretsMgr.Status()
	if err != nil {
		t.Errorf("Status should not fail when database doesn't exist: %v", err)
	}
}

// TestStatus_WithIgnoreConfigFile tests status command with --ignore-config-file
func TestStatus_WithIgnoreConfigFile(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Setup mock KeePass manager
	mockKP := newMockKeePassManager()
	// Configure mock for valid database with proper structure
	mockKP.db = &gokeepasslib.Database{
		Content: &gokeepasslib.DBContent{
			Root: &gokeepasslib.RootData{
				Groups: []gokeepasslib.Group{
					{Name: "Root", Groups: []gokeepasslib.Group{}},
				},
			},
		},
	}

	// Setup managers with IgnoreConfigFile=true
	flags := &types.GlobalFlags{
		Force:            true,
		IgnoreConfigFile: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, &types.CommandFlags{}, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKP, output.NewManager(), validator.NewManager())

	// Setup infrastructure first
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Initialize first
	err = secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Run status
	err = secretsMgr.Status()
	if err != nil {
		t.Errorf("Status failed with --ignore-config-file: %v", err)
	}

	// Verify config file was NOT created
	secretsDir := filepath.Join(tmpDir, ".secrets_yohnah")
	configPath := filepath.Join(secretsDir, "config.yml")
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Error("Config file should not exist with --ignore-config-file")
	}
}

// TestStatus_WithCustomPaths tests status command with custom database and keyfile paths
func TestStatus_WithCustomPaths(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Create custom paths
	customDir := filepath.Join(tmpDir, "custom")
	if err := os.MkdirAll(customDir, 0755); err != nil {
		t.Fatalf("Failed to create custom directory: %v", err)
	}
	dbPath := filepath.Join(customDir, "my-database.kdbx")
	keyfilePath := filepath.Join(customDir, "my-keyfile")

	// Setup managers
	flags := &types.GlobalFlags{
		Database: dbPath,
		Keyfile:  keyfilePath,
		Force:    true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, &types.CommandFlags{}, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), validator.NewManager())

	// Setup infrastructure first
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Initialize first
	err = secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed with custom paths: %v", err)
	}

	// Run status
	err = secretsMgr.Status()
	if err != nil {
		t.Errorf("Status failed with custom paths: %v", err)
	}

	// Verify files exist at custom locations
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database file should exist at custom path")
	}
	if _, err := os.Stat(keyfilePath); os.IsNotExist(err) {
		t.Error("Keyfile should exist at custom path")
	}
}

// TestStatus_WithWrongPassword tests status command with incorrect password
func TestStatus_WithWrongPassword(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Setup managers
	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, &types.CommandFlags{}, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), validator.NewManager())

	// Setup infrastructure first
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Initialize with correct password
	err = secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Change to wrong password
	os.Setenv("SECRETS_YOHNAH_PASSWORD", "wrong-password")

	// Run status (should not fail, but should report database not accessible)
	err = secretsMgr.Status()
	if err != nil {
		t.Errorf("Status should not fail with wrong password, just report inaccessible: %v", err)
	}
}

// TestStatus_AfterInit tests that status works immediately after init
func TestStatus_AfterInit(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Setup managers
	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, &types.CommandFlags{}, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), validator.NewManager())

	// Setup infrastructure first
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Initialize
	err = secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Immediately run status (should work)
	err = secretsMgr.Status()
	if err != nil {
		t.Errorf("Status failed after init: %v", err)
	}

	// Verify all files exist
	secretsDir := filepath.Join(tmpDir, ".secrets_yohnah")
	dbPath := filepath.Join(secretsDir, "secrets.kdbx")
	keyfilePath := filepath.Join(secretsDir, "secrets.keyfile")
	configPath := filepath.Join(secretsDir, "config.yml")

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database file should exist")
	}
	if _, err := os.Stat(keyfilePath); os.IsNotExist(err) {
		t.Error("Keyfile should exist")
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Config file should exist")
	}
}
