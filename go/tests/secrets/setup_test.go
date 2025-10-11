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

// TestSetupWithSetupDirInHome validates --setup-dir-in-home flag
func TestSetupWithSetupDirInHome(t *testing.T) {
	// Create temporary home directory for testing
	tmpHome := setupTestDir(t)
	defer os.RemoveAll(tmpHome)

	// Set HOME environment variable to temp directory
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", originalHome)

	// Create temp project directory
	tmpProject := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpProject)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpProject)

	flags := &types.GlobalFlags{
		Force: true, // Non-interactive mode
	}
	cmdFlags := &types.CommandFlags{
		SetupDirInHome: true, // Use home directory
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, cmdFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), validator.NewManager())

	// Execute setup
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup with --setup-dir-in-home failed: %v", err)
	}

	// Verify directory was created in HOME, not in project
	homeSecretsDir := filepath.Join(tmpHome, ".yohnah", "secrets")
	if _, err := os.Stat(homeSecretsDir); os.IsNotExist(err) {
		t.Errorf("Home secrets directory was not created at %s", homeSecretsDir)
	}

	// Verify project directory was NOT created
	projectSecretsDir := filepath.Join(tmpProject, ".secrets_yohnah")
	if _, err := os.Stat(projectSecretsDir); err == nil {
		t.Errorf("Project secrets directory should not have been created")
	}

	// Verify files exist in home directory
	configPath := filepath.Join(homeSecretsDir, "config.yml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Errorf("config.yml was not created in home directory")
	}

	dbPath := filepath.Join(homeSecretsDir, "secrets.kdbx")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("database was not created in home directory")
	}

	keyfilePath := filepath.Join(homeSecretsDir, "secrets.keyfile")
	if _, err := os.Stat(keyfilePath); os.IsNotExist(err) {
		t.Errorf("keyfile was not created in home directory")
	}
}

// TestSetupPrevalenceProjectExists validates that existing project directory takes precedence
func TestSetupPrevalenceProjectExists(t *testing.T) {
	// Create temporary home directory with existing setup
	tmpHome := setupTestDir(t)
	defer os.RemoveAll(tmpHome)

	// Set HOME environment variable
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", originalHome)

	// Create existing home directory
	homeSecretsDir := filepath.Join(tmpHome, ".yohnah", "secrets")
	os.MkdirAll(homeSecretsDir, 0700)

	// Create temp project directory with existing .secrets_yohnah
	tmpProject := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpProject)
	projectSecretsDir := filepath.Join(tmpProject, ".secrets_yohnah")
	os.MkdirAll(projectSecretsDir, 0700)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpProject)

	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, &types.CommandFlags{}, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	mockKeePass := newMockKeePassManager()

	// Pre-create database and keyfile in project directory
	dbPath := filepath.Join(projectSecretsDir, "secrets.kdbx")
	keyfilePath := filepath.Join(projectSecretsDir, "secrets.keyfile")
	mockKeePass.GenerateKeyfile(keyfilePath)
	mockKeePass.CreateDatabase(dbPath, keyfilePath, "test123", "Test")

	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKeePass, output.NewManager(), validator.NewManager())

	// Execute setup - should detect existing project directory
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Verify it used the project directory (both should exist but project takes precedence)
	if _, err := os.Stat(projectSecretsDir); os.IsNotExist(err) {
		t.Errorf("Project secrets directory should exist")
	}
}

// TestSetupDefaultsToProjectNotHome validates that project directory is used by default (even when home exists)
func TestSetupDefaultsToProjectNotHome(t *testing.T) {
	// Create temporary home directory with existing setup
	tmpHome := setupTestDir(t)
	defer os.RemoveAll(tmpHome)

	// Set HOME environment variable
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", originalHome)

	// Create existing home directory with database
	homeSecretsDir := filepath.Join(tmpHome, ".yohnah", "secrets")
	os.MkdirAll(homeSecretsDir, 0700)

	setupTestPassword(t)

	// Pre-create database and keyfile in home directory
	mockKeePass := newMockKeePassManager()
	dbPath := filepath.Join(homeSecretsDir, "secrets.kdbx")
	keyfilePath := filepath.Join(homeSecretsDir, "secrets.keyfile")
	mockKeePass.GenerateKeyfile(keyfilePath)
	mockKeePass.CreateDatabase(dbPath, keyfilePath, "test123", "Test")

	// Create temp project directory WITHOUT .secrets_yohnah
	tmpProject := setupTestDir(t)
	initGitRepo(t, tmpProject)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpProject)

	flags := &types.GlobalFlags{
		Force: true, // Non-interactive mode
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, &types.CommandFlags{}, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKeePass, output.NewManager(), validator.NewManager())

	// Execute setup - should create in project directory by default (NOT use existing home)
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Verify it created in project directory (default behavior)
	projectSecretsDir := filepath.Join(tmpProject, ".secrets_yohnah")
	if _, err := os.Stat(projectSecretsDir); os.IsNotExist(err) {
		t.Errorf("Project secrets directory should have been created (default behavior)")
	}

	// Verify both directories exist (coexistence is allowed)
	if _, err := os.Stat(homeSecretsDir); os.IsNotExist(err) {
		t.Errorf("Home secrets directory should still exist")
	}
}

// TestSetupForceRecreateOnlyAffectsProject validates that --force-recreate only deletes project directory
func TestSetupForceRecreateOnlyAffectsProject(t *testing.T) {
	// Create temporary home directory with existing setup
	tmpHome := setupTestDir(t)
	defer os.RemoveAll(tmpHome)

	// Set HOME environment variable
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", originalHome)

	// Create existing home directory
	homeSecretsDir := filepath.Join(tmpHome, ".yohnah", "secrets")
	os.MkdirAll(homeSecretsDir, 0700)

	setupTestPassword(t)

	// Pre-create database and keyfile in home directory
	mockKeePass := newMockKeePassManager()
	homeDbPath := filepath.Join(homeSecretsDir, "secrets.kdbx")
	homeKeyfilePath := filepath.Join(homeSecretsDir, "secrets.keyfile")
	mockKeePass.GenerateKeyfile(homeKeyfilePath)
	mockKeePass.CreateDatabase(homeDbPath, homeKeyfilePath, "test123", "Test")

	// Create marker file in home directory to verify it's not touched
	markerFile := filepath.Join(homeSecretsDir, "marker.txt")
	os.WriteFile(markerFile, []byte("do not delete"), 0600)

	// Create temp project directory with existing .secrets_yohnah
	tmpProject := setupTestDir(t)
	initGitRepo(t, tmpProject)
	projectSecretsDir := filepath.Join(tmpProject, ".secrets_yohnah")
	os.MkdirAll(projectSecretsDir, 0700)

	// Create marker file in project directory to verify it IS deleted
	projectMarker := filepath.Join(projectSecretsDir, "project_marker.txt")
	os.WriteFile(projectMarker, []byte("should be deleted"), 0600)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpProject)

	flags := &types.GlobalFlags{
		Force: true,
	}
	cmdFlags := &types.CommandFlags{
		ForceRecreate: true, // Should delete project directory only
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, cmdFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKeePass, output.NewManager(), validator.NewManager())

	// Execute setup with --force-recreate
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Verify home directory still exists and marker file is intact
	if _, err := os.Stat(markerFile); os.IsNotExist(err) {
		t.Errorf("Home directory marker file should NOT have been deleted")
	}

	// Verify project marker file was deleted (directory was recreated)
	if _, err := os.Stat(projectMarker); err == nil {
		t.Errorf("Project directory marker file SHOULD have been deleted")
	}

	// Verify new project directory was created
	if _, err := os.Stat(projectSecretsDir); os.IsNotExist(err) {
		t.Errorf("Project secrets directory should have been recreated")
	}
}

// TestSetupBothDirectoriesCanCoexist validates that both directories can exist simultaneously
func TestSetupBothDirectoriesCanCoexist(t *testing.T) {
	// Create temporary home directory
	tmpHome := setupTestDir(t)
	defer os.RemoveAll(tmpHome)

	// Set HOME environment variable
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", originalHome)

	setupTestPassword(t)

	// Create temp project directory
	tmpProject1 := setupTestDir(t)
	initGitRepo(t, tmpProject1)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpProject1)

	mockKeePass := newMockKeePassManager()
	validatorMgr := validator.NewManager()
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()

	// First create in project (when home doesn't exist yet)
	flags1 := &types.GlobalFlags{
		Force: true,
	}

	configMgr1 := config.NewManager(flags1, &types.CommandFlags{}, validatorMgr)
	secretsMgr1 := secrets.NewManager(configMgr1, loggerMgr, promptMgr, mockKeePass, output.NewManager(), validator.NewManager())

	err := secretsMgr1.Setup()
	if err != nil {
		t.Fatalf("Setup in project failed: %v", err)
	}

	// Then create in home
	flags2 := &types.GlobalFlags{
		Force: true,
	}
	cmdFlags2 := &types.CommandFlags{
		SetupDirInHome: true,
	}

	configMgr2 := config.NewManager(flags2, cmdFlags2, validatorMgr)
	secretsMgr2 := secrets.NewManager(configMgr2, loggerMgr, promptMgr, mockKeePass, output.NewManager(), validator.NewManager())

	err = secretsMgr2.Setup()
	if err != nil {
		t.Fatalf("Setup in home failed: %v", err)
	}

	// Verify both directories exist
	homeSecretsDir := filepath.Join(tmpHome, ".yohnah", "secrets")
	if _, err := os.Stat(homeSecretsDir); os.IsNotExist(err) {
		t.Errorf("Home secrets directory should exist")
	}

	projectSecretsDir := filepath.Join(tmpProject1, ".secrets_yohnah")
	if _, err := os.Stat(projectSecretsDir); os.IsNotExist(err) {
		t.Errorf("Project secrets directory should exist")
	}

	// Verify files in both directories
	homeDb := filepath.Join(homeSecretsDir, "secrets.kdbx")
	projectDb := filepath.Join(projectSecretsDir, "secrets.kdbx")

	if _, err := os.Stat(homeDb); os.IsNotExist(err) {
		t.Errorf("Home database should exist")
	}

	if _, err := os.Stat(projectDb); os.IsNotExist(err) {
		t.Errorf("Project database should exist")
	}
}
