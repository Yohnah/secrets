package secrets_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/output"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/Yohnah/secrets/internal/types"
	"github.com/Yohnah/secrets/internal/validator"
)

// TestStatus_WithValidDatabase tests status command with accessible database
func TestStatus_WithValidDatabase(t *testing.T) {
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
	configMgr := config.NewManager(flags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validator.NewManager())

	// Initialize first
	err := secretsMgr.Init(secrets.InitOptions{})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Run status
	err = secretsMgr.Status("table")
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

	// Setup managers without initializing
	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validator.NewManager())

	// Run status without initializing first
	err := secretsMgr.Status("table")
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

	// Setup managers with IgnoreConfigFile=true
	flags := &types.GlobalFlags{
		Force:            true,
		IgnoreConfigFile: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validator.NewManager())

	// Initialize first
	err := secretsMgr.Init(secrets.InitOptions{})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Run status
	err = secretsMgr.Status("table")
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

	// Setup custom paths
	customDir := filepath.Join(tmpDir, "custom")
	dbPath := filepath.Join(customDir, "my-database.kdbx")
	keyfilePath := filepath.Join(customDir, "my-keyfile.key")

	// Create custom directory
	if err := os.MkdirAll(customDir, 0755); err != nil {
		t.Fatalf("Failed to create custom directory: %v", err)
	}

	// Setup managers with custom paths
	flags := &types.GlobalFlags{
		Force:    true,
		Database: dbPath,
		Keyfile:  keyfilePath,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validator.NewManager())

	// Initialize first
	err := secretsMgr.Init(secrets.InitOptions{})
	if err != nil {
		t.Fatalf("Init failed with custom paths: %v", err)
	}

	// Run status
	err = secretsMgr.Status("table")
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
	configMgr := config.NewManager(flags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validator.NewManager())

	// Initialize with correct password
	err := secretsMgr.Init(secrets.InitOptions{})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Change to wrong password
	os.Setenv("SECRETS_YOHNAH_PASSWORD", "wrong-password")

	// Run status (should not fail, but should report database not accessible)
	err = secretsMgr.Status("table")
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
	configMgr := config.NewManager(flags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validator.NewManager())

	// Initialize
	err := secretsMgr.Init(secrets.InitOptions{})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Immediately run status (should work)
	err = secretsMgr.Status("table")
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
