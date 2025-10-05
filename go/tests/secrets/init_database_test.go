package secrets_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/Yohnah/secrets/internal/types"
)

// TestInitCreatesDatabaseAndKeyfile tests that init creates KeePass database and keyfile
func TestInitCreatesDatabaseAndKeyfile(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	flags := &types.GlobalFlags{
		Force: true,
	}

	configMgr := config.NewManager(flags)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr)

	err := secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify database was created
	dbPath := filepath.Join(tmpDir, ".secrets_yohnah", "secrets.kdbx")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("Database file was not created: %s", dbPath)
	}

	// Verify keyfile was created
	keyfilePath := filepath.Join(tmpDir, ".secrets_yohnah", "secrets.keyfile")
	if _, err := os.Stat(keyfilePath); os.IsNotExist(err) {
		t.Errorf("Keyfile was not created: %s", keyfilePath)
	}

	// Verify keyfile has correct permissions (0600)
	info, err := os.Stat(keyfilePath)
	if err != nil {
		t.Fatalf("Failed to stat keyfile: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("Keyfile has incorrect permissions. Expected 0600, got %o", info.Mode().Perm())
	}

	// Verify keyfile has correct size (64 bytes)
	if info.Size() != 64 {
		t.Errorf("Keyfile has incorrect size. Expected 64 bytes, got %d", info.Size())
	}
}

// TestInitVerifiesExistingDatabase tests that init verifies access to existing database
func TestInitVerifiesExistingDatabase(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	flags := &types.GlobalFlags{
		Force: true,
	}

	// First init - creates database
	configMgr1 := config.NewManager(flags)
	loggerMgr1 := logger.NewManager(false)
	promptMgr1 := prompt.NewManager()
	secretsMgr1 := secrets.NewManager(configMgr1, loggerMgr1, promptMgr1)

	err := secretsMgr1.Init()
	if err != nil {
		t.Fatalf("First init failed: %v", err)
	}

	// Get modification times
	dbPath := filepath.Join(tmpDir, ".secrets_yohnah", "secrets.kdbx")
	keyfilePath := filepath.Join(tmpDir, ".secrets_yohnah", "secrets.keyfile")

	dbInfo1, _ := os.Stat(dbPath)
	keyInfo1, _ := os.Stat(keyfilePath)

	// Wait a bit to ensure different timestamps if files were recreated
	time.Sleep(100 * time.Millisecond)

	// Second init - should verify, not recreate
	configMgr2 := config.NewManager(flags)
	loggerMgr2 := logger.NewManager(false)
	promptMgr2 := prompt.NewManager()
	secretsMgr2 := secrets.NewManager(configMgr2, loggerMgr2, promptMgr2)

	err = secretsMgr2.Init()
	if err != nil {
		t.Fatalf("Second init failed: %v", err)
	}

	// Verify files were not recreated
	dbInfo2, _ := os.Stat(dbPath)
	keyInfo2, _ := os.Stat(keyfilePath)

	if !dbInfo2.ModTime().Equal(dbInfo1.ModTime()) {
		t.Errorf("Database was recreated instead of verified")
	}

	if !keyInfo2.ModTime().Equal(keyInfo1.ModTime()) {
		t.Errorf("Keyfile was recreated instead of verified")
	}
}

// TestInitWithForceRecreate tests that --force-recreate flag deletes and recreates everything
func TestInitWithForceRecreate(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// First init - creates database
	flags1 := &types.GlobalFlags{
		Force: true,
	}

	configMgr1 := config.NewManager(flags1)
	loggerMgr1 := logger.NewManager(false)
	promptMgr1 := prompt.NewManager()
	secretsMgr1 := secrets.NewManager(configMgr1, loggerMgr1, promptMgr1)

	err := secretsMgr1.Init()
	if err != nil {
		t.Fatalf("First init failed: %v", err)
	}

	// Get modification times
	dbPath := filepath.Join(tmpDir, ".secrets_yohnah", "secrets.kdbx")
	keyfilePath := filepath.Join(tmpDir, ".secrets_yohnah", "secrets.keyfile")

	dbInfo1, _ := os.Stat(dbPath)
	keyInfo1, _ := os.Stat(keyfilePath)
	originalDbModTime := dbInfo1.ModTime()
	originalKeyModTime := keyInfo1.ModTime()

	// Wait to ensure different timestamps
	time.Sleep(100 * time.Millisecond)

	// Second init with force-recreate - should delete and recreate
	configMgr2 := config.NewManager(flags1)
	loggerMgr2 := logger.NewManager(false)
	promptMgr2 := prompt.NewManager()
	secretsMgr2 := secrets.NewManager(configMgr2, loggerMgr2, promptMgr2)

	err = secretsMgr2.InitWithRecreate(true)
	if err != nil {
		t.Fatalf("Second init with force-recreate failed: %v", err)
	}

	// Verify files were recreated (different modification times)
	dbInfo2, _ := os.Stat(dbPath)
	keyInfo2, _ := os.Stat(keyfilePath)

	if dbInfo2.ModTime().Equal(originalDbModTime) {
		t.Errorf("Database was not recreated with --force-recreate")
	}

	if keyInfo2.ModTime().Equal(originalKeyModTime) {
		t.Errorf("Keyfile was not recreated with --force-recreate")
	}
}

// TestInitFailsWithInconsistentFiles tests that init fails if only database OR keyfile exists
func TestInitFailsWithInconsistentFiles(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Create .secrets_yohnah directory and config.yml
	secretsDir := filepath.Join(tmpDir, ".secrets_yohnah")
	os.MkdirAll(secretsDir, 0755)

	configFile := filepath.Join(secretsDir, "config.yml")
	os.WriteFile(configFile, []byte("database: .secrets_yohnah/secrets.kdbx\nkeyfile: .secrets_yohnah/secrets.keyfile\n"), 0644)

	// Test 1: Only database exists (no keyfile)
	dbPath := filepath.Join(secretsDir, "secrets.kdbx")
	os.WriteFile(dbPath, []byte("dummy db content"), 0644)

	flags := &types.GlobalFlags{
		Force: true,
	}

	configMgr := config.NewManager(flags)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr)

	err := secretsMgr.Init()
	if err == nil {
		t.Errorf("Init should have failed when only database exists without keyfile")
	}

	// Clean up
	os.Remove(dbPath)

	// Test 2: Only keyfile exists (no database)
	keyfilePath := filepath.Join(secretsDir, "secrets.keyfile")
	os.WriteFile(keyfilePath, []byte("dummy keyfile content"), 0600)

	configMgr2 := config.NewManager(flags)
	loggerMgr2 := logger.NewManager(false)
	promptMgr2 := prompt.NewManager()
	secretsMgr2 := secrets.NewManager(configMgr2, loggerMgr2, promptMgr2)

	err = secretsMgr2.Init()
	if err == nil {
		t.Errorf("Init should have failed when only keyfile exists without database")
	}
}

// TestInitWithWrongPassword tests that init fails with wrong password
func TestInitWithWrongPassword(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t) // Sets "test-password-123"
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	flags := &types.GlobalFlags{
		Force: true,
	}

	// First init - creates database with "test-password-123"
	configMgr1 := config.NewManager(flags)
	loggerMgr1 := logger.NewManager(false)
	promptMgr1 := prompt.NewManager()
	secretsMgr1 := secrets.NewManager(configMgr1, loggerMgr1, promptMgr1)

	err := secretsMgr1.Init()
	if err != nil {
		t.Fatalf("First init failed: %v", err)
	}

	// Change password to wrong one
	os.Setenv("SECRETS_YOHNAH_PASSWORD", "wrong-password")
	t.Cleanup(func() {
		os.Unsetenv("SECRETS_YOHNAH_PASSWORD")
	})

	// Second init - should fail with wrong password
	configMgr2 := config.NewManager(flags)
	loggerMgr2 := logger.NewManager(false)
	promptMgr2 := prompt.NewManager()
	secretsMgr2 := secrets.NewManager(configMgr2, loggerMgr2, promptMgr2)

	err = secretsMgr2.Init()
	if err == nil {
		t.Errorf("Init should have failed with wrong password")
	}
}

// TestInitWithoutPasswordInNonInteractiveMode tests that init fails without password in -f mode
func TestInitWithoutPasswordInNonInteractiveMode(t *testing.T) {
	tmpDir := setupTestDir(t)
	// Don't call setupTestPassword() - no password set
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	flags := &types.GlobalFlags{
		Force: true, // Non-interactive mode
	}

	configMgr := config.NewManager(flags)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr)

	err := secretsMgr.Init()
	if err == nil {
		t.Errorf("Init should have failed without password in non-interactive mode")
	}
}
