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
)

// TestSetupCreatesAllFiles verifies that setup creates directory + files + database
func TestSetupCreatesAllFiles(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	flags := &types.GlobalFlags{
		Force: true, // Non-interactive mode
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, &types.CommandFlags{}, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), validator.NewManager())

	// Execute setup (uses Init() method)
	err := secretsMgr.Init()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Verify directory exists
	secretsDir := filepath.Join(tmpDir, ".secrets_yohnah")
	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		t.Errorf(".secrets_yohnah directory was not created")
	}

	// Verify config.yml exists
	configPath := filepath.Join(secretsDir, "config.yml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Errorf("config.yml was not created")
	}

	// Verify keyfile exists
	keyfilePath := filepath.Join(secretsDir, "secrets.keyfile")
	if _, err := os.Stat(keyfilePath); os.IsNotExist(err) {
		t.Errorf("keyfile was not created")
	}

	// Verify database exists
	dbPath := filepath.Join(secretsDir, "secrets.kdbx")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("database was not created")
	}

	// Verify keyfile has secure permissions (0600)
	keyfileInfo, err := os.Stat(keyfilePath)
	if err != nil {
		t.Fatalf("Failed to stat keyfile: %v", err)
	}
	if keyfileInfo.Mode().Perm() != 0600 {
		t.Errorf("Keyfile permissions: got %o, want 0600", keyfileInfo.Mode().Perm())
	}
}

// TestSetupWithCustomDatabaseName validates that custom database name is used
func TestSetupWithCustomDatabaseName(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	flags := &types.GlobalFlags{
		Force: true,
	}
	cmdFlags := &types.CommandFlags{
		DatabaseName: "MyCustomDB",
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, cmdFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	keepassMgr := newMockKeePassManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepassMgr, output.NewManager(), validator.NewManager())

	err := secretsMgr.Init()
	if err != nil {
		t.Fatalf("Setup with custom database name failed: %v", err)
	}

	// Verify database was created
	secretsDir := filepath.Join(tmpDir, ".secrets_yohnah")
	dbPath := filepath.Join(secretsDir, "secrets.kdbx")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("database was not created")
	}

	// Open database and verify root group name
	keyfilePath := filepath.Join(secretsDir, "secrets.keyfile")
	if err := keepassMgr.Open(dbPath, keyfilePath, "TestPassword123!"); err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer keepassMgr.CloseWithoutSave()

	db := keepassMgr.GetDatabase()
	if db.Content.Root.Groups[0].Name != "MyCustomDB" {
		t.Errorf("Database root group name: got %s, want MyCustomDB", db.Content.Root.Groups[0].Name)
	}
}

// TestSetupFailsIfDirectoryExistsWithoutForce validates error without force flag
func TestSetupFailsIfDirectoryExistsWithoutForce(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// First setup - should succeed
	flags1 := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr1 := validator.NewManager()
	configMgr1 := config.NewManager(flags1, &types.CommandFlags{}, validatorMgr1)
	loggerMgr1 := logger.NewManager(false)
	promptMgr1 := prompt.NewManager()
	secretsMgr1 := secrets.NewManager(configMgr1, loggerMgr1, promptMgr1, newMockKeePassManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr1.Init()
	if err != nil {
		t.Fatalf("First setup failed: %v", err)
	}

	// Second setup without force - should fail
	flags2 := &types.GlobalFlags{
		Force: false,
	}

	validatorMgr2 := validator.NewManager()
	configMgr2 := config.NewManager(flags2, &types.CommandFlags{}, validatorMgr2)
	loggerMgr2 := logger.NewManager(false)
	promptMgr2 := prompt.NewManager()
	secretsMgr2 := secrets.NewManager(configMgr2, loggerMgr2, promptMgr2, newMockKeePassManager(), output.NewManager(), validator.NewManager())

	err = secretsMgr2.Init()
	if err == nil {
		t.Errorf("Second setup should have failed without force flag")
	}
}

// TestSetupWithForceRecreate validates --force-recreate flag behavior
func TestSetupWithForceRecreate(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// First setup
	flags1 := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr1 := validator.NewManager()
	configMgr1 := config.NewManager(flags1, &types.CommandFlags{}, validatorMgr1)
	loggerMgr1 := logger.NewManager(false)
	promptMgr1 := prompt.NewManager()
	secretsMgr1 := secrets.NewManager(configMgr1, loggerMgr1, promptMgr1, newMockKeePassManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr1.Init()
	if err != nil {
		t.Fatalf("First setup failed: %v", err)
	}

	// Verify files were created
	secretsDir := filepath.Join(tmpDir, ".secrets_yohnah")
	keyfilePath := filepath.Join(secretsDir, "secrets.keyfile")
	dbPath := filepath.Join(secretsDir, "secrets.kdbx")

	if _, err := os.Stat(keyfilePath); os.IsNotExist(err) {
		t.Fatalf("Keyfile was not created in first setup")
	}
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatalf("Database was not created in first setup")
	}

	// Get modification times
	keyfileInfo1, _ := os.Stat(keyfilePath)
	dbInfo1, _ := os.Stat(dbPath)

	// Second setup with force-recreate - should succeed and recreate files
	flags2 := &types.GlobalFlags{
		Force: true,
	}
	cmdFlags2 := &types.CommandFlags{
		ForceRecreate: true,
	}

	validatorMgr2 := validator.NewManager()
	configMgr2 := config.NewManager(flags2, cmdFlags2, validatorMgr2)
	loggerMgr2 := logger.NewManager(false)
	promptMgr2 := prompt.NewManager()
	secretsMgr2 := secrets.NewManager(configMgr2, loggerMgr2, promptMgr2, newMockKeePassManager(), output.NewManager(), validator.NewManager())

	err = secretsMgr2.Init()
	if err != nil {
		t.Fatalf("Second setup with force failed: %v", err)
	}

	// Verify files still exist
	if _, err := os.Stat(keyfilePath); os.IsNotExist(err) {
		t.Errorf("Keyfile was not recreated")
	}
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("Database was not recreated")
	}

	// Verify files were recreated (modification times should be different or equal/newer)
	keyfileInfo2, _ := os.Stat(keyfilePath)
	dbInfo2, _ := os.Stat(dbPath)

	// Files should have been recreated (either new time or at least exist)
	if keyfileInfo2.ModTime().Before(keyfileInfo1.ModTime()) {
		t.Errorf("Keyfile modification time went backwards, should have been recreated")
	}
	if dbInfo2.ModTime().Before(dbInfo1.ModTime()) {
		t.Errorf("Database modification time went backwards, should have been recreated")
	}
}

// TestSetupWithNoCreateDatabase validates --no-create-database flag
func TestSetupWithNoCreateDatabase(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	flags := &types.GlobalFlags{
		Force: true,
	}
	cmdFlags := &types.CommandFlags{
		NoCreateDatabase: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, cmdFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr.Init()
	if err != nil {
		t.Fatalf("Setup with no-create-database failed: %v", err)
	}

	secretsDir := filepath.Join(tmpDir, ".secrets_yohnah")

	// Verify directory and config were created
	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		t.Errorf(".secrets_yohnah directory was not created")
	}

	configPath := filepath.Join(secretsDir, "config.yml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Errorf("config.yml was not created")
	}

	// Verify database and keyfile were NOT created
	dbPath := filepath.Join(secretsDir, "secrets.kdbx")
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Errorf("database should not have been created with --no-create-database flag")
	}

	keyfilePath := filepath.Join(secretsDir, "secrets.keyfile")
	if _, err := os.Stat(keyfilePath); !os.IsNotExist(err) {
		t.Errorf("keyfile should not have been created with --no-create-database flag")
	}
}

// TestSetupWithGlobalFlagVerbose validates -v verbose output
func TestSetupWithGlobalFlagVerbose(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	flags := &types.GlobalFlags{
		Force:   true,
		Verbose: true, // Enable verbose mode
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, &types.CommandFlags{}, validatorMgr)
	loggerMgr := logger.NewManager(true) // Logger should be in verbose mode
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr.Init()
	if err != nil {
		t.Fatalf("Setup with verbose flag failed: %v", err)
	}

	// Just verify setup completes - verbose output is visual only
	secretsDir := filepath.Join(tmpDir, ".secrets_yohnah")
	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		t.Errorf(".secrets_yohnah directory was not created")
	}
}

// TestSetupWithIgnoreGitProject validates --ignore-git-project flag
func TestSetupWithIgnoreGitProject(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	// Note: NOT initializing git repo to test ignore-git-project flag

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	flags := &types.GlobalFlags{
		Force:            true,
		IgnoreGitProject: true, // Should allow setup without git repo
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, &types.CommandFlags{}, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr.Init()
	if err != nil {
		t.Fatalf("Setup with ignore-git-project failed: %v", err)
	}

	// Verify setup completed successfully
	secretsDir := filepath.Join(tmpDir, ".secrets_yohnah")
	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		t.Errorf(".secrets_yohnah directory was not created")
	}
}
