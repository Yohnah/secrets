package secrets_test

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/output"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/Yohnah/secrets/internal/types"
	"github.com/Yohnah/secrets/internal/validator"
)

func TestSnapshotsRestore_Success(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create secrets.yml with a profile
	secretsYMLContent := `metadata:
  profile: "test-profile"

environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Production/DB"
      key: "Password"

outputs: []`

	secretsYMLPath := filepath.Join(tmpDir, "secrets.yml")
	if err := os.WriteFile(secretsYMLPath, []byte(secretsYMLContent), 0644); err != nil {
		t.Fatalf("Failed to create secrets.yml: %v", err)
	}

	// Change to tmpDir
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Setup mock KeePass manager
	mockKP := newMockKeePassManager()
	mockKP.setupProfileWithSnapshots("test-profile", []string{"v1", "v2"})

	// Setup managers
	flags := &types.GlobalFlags{
		SecretsFile:      secretsYMLPath,
		IgnoreGitProject: true,
		Force:            true,
	}

	commandFlags := &types.CommandFlags{}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, commandFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKP, output.NewManager(), validatorMgr)

	// Restore v1
	err := secretsMgr.SnapshotsRestore("test-profile", "v1")
	if err != nil {
		t.Fatalf("SnapshotsRestore failed: %v", err)
	}

	// Verify that HEAD was renamed to v3
	v3Exists, _ := mockKP.TreeGroupExists("test-profile", "v3")
	if !v3Exists {
		t.Errorf("Expected v3 to exist after restore (old HEAD)")
	}

	// Verify that new HEAD exists
	headExists, _ := mockKP.TreeGroupExists("test-profile", "HEAD")
	if !headExists {
		t.Errorf("Expected HEAD to exist after restore")
	}

	// Verify that new HEAD has version 4
	newVersion, _ := mockKP.GetTreeGroupEntryField("test-profile", "HEAD", "metadata", "version")
	if newVersion != "4" {
		t.Errorf("Expected new HEAD version to be 4, got %s", newVersion)
	}

	// Verify SaveAndClose was called
	if !mockKP.saveAndCloseCalled {
		t.Errorf("Expected SaveAndClose to be called")
	}
}

func TestSnapshotsRestore_ProfileNotInSecretsYML(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create secrets.yml with a different profile
	secretsYMLContent := `metadata:
  profile: "test-profile"

environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Production/DB"
      key: "Password"

outputs: []`

	secretsYMLPath := filepath.Join(tmpDir, "secrets.yml")
	if err := os.WriteFile(secretsYMLPath, []byte(secretsYMLContent), 0644); err != nil {
		t.Fatalf("Failed to create secrets.yml: %v", err)
	}

	// Change to tmpDir
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Setup mock KeePass manager
	mockKP := newMockKeePassManager()

	// Setup managers
	flags := &types.GlobalFlags{
		SecretsFile:      secretsYMLPath,
		IgnoreGitProject: true,
		Force:            true,
	}

	commandFlags := &types.CommandFlags{}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, commandFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKP, output.NewManager(), validatorMgr)

	// Try to restore for non-existent profile
	err := secretsMgr.SnapshotsRestore("non-existent-profile", "v1")
	if err == nil {
		t.Fatal("Expected error for non-existent profile, but got nil")
	}

	// Verify error message
	expectedMsg := "does not exist in secrets.yml"
	if !contains(err.Error(), expectedMsg) {
		t.Errorf("Expected error message to contain '%s', got: %s", expectedMsg, err.Error())
	}
}

func TestSnapshotsRestore_SnapshotNotExists(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create secrets.yml with a profile
	secretsYMLContent := `metadata:
  profile: "test-profile"

environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Production/DB"
      key: "Password"

outputs: []`

	secretsYMLPath := filepath.Join(tmpDir, "secrets.yml")
	if err := os.WriteFile(secretsYMLPath, []byte(secretsYMLContent), 0644); err != nil {
		t.Fatalf("Failed to create secrets.yml: %v", err)
	}

	// Change to tmpDir
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Setup mock KeePass manager
	mockKP := newMockKeePassManager()
	mockKP.CreateProfile("test-profile") // Profile exists but no snapshots

	// Setup managers
	flags := &types.GlobalFlags{
		SecretsFile:      secretsYMLPath,
		IgnoreGitProject: true,
		Force:            true,
	}

	commandFlags := &types.CommandFlags{}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, commandFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKP, output.NewManager(), validatorMgr)

	// Try to restore non-existent snapshot
	err := secretsMgr.SnapshotsRestore("test-profile", "v999")
	if err == nil {
		t.Fatal("Expected error for non-existent snapshot, but got nil")
	}

	// Verify error message
	expectedMsg := "does not exist for profile"
	if !contains(err.Error(), expectedMsg) {
		t.Errorf("Expected error message to contain '%s', got: %s", expectedMsg, err.Error())
	}
}

func TestSnapshotsRestore_VersionIncrement(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create secrets.yml
	secretsYMLContent := `metadata:
  profile: "test-profile"

environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Production/DB"
      key: "Password"

outputs: []`

	secretsYMLPath := filepath.Join(tmpDir, "secrets.yml")
	if err := os.WriteFile(secretsYMLPath, []byte(secretsYMLContent), 0644); err != nil {
		t.Fatalf("Failed to create secrets.yml: %v", err)
	}

	// Change to tmpDir
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Setup mock with multiple versions
	mockKP := newMockKeePassManager()
	mockKP.setupProfileWithSnapshots("test-profile", []string{"v1", "v2", "v3", "v4", "v5"})

	// Setup managers
	flags := &types.GlobalFlags{
		SecretsFile:      secretsYMLPath,
		IgnoreGitProject: true,
		Force:            true,
	}

	commandFlags := &types.CommandFlags{}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, commandFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKP, output.NewManager(), validatorMgr)

	// Get HEAD version before restore (should be 6)
	headVersionBefore, _ := mockKP.GetTreeGroupEntryField("test-profile", "HEAD", "metadata", "version")
	if headVersionBefore != "6" {
		t.Fatalf("Expected HEAD version to be 6 before restore, got %s", headVersionBefore)
	}

	// Restore v2
	err := secretsMgr.SnapshotsRestore("test-profile", "v2")
	if err != nil {
		t.Fatalf("SnapshotsRestore failed: %v", err)
	}

	// Verify old HEAD was saved as v6
	v6Exists, _ := mockKP.TreeGroupExists("test-profile", "v6")
	if !v6Exists {
		t.Errorf("Expected v6 to exist (old HEAD)")
	}

	// Verify new HEAD version is 7
	newVersion, _ := mockKP.GetTreeGroupEntryField("test-profile", "HEAD", "metadata", "version")
	expectedVersion := strconv.Itoa(7)
	if newVersion != expectedVersion {
		t.Errorf("Expected new HEAD version to be %s, got %s", expectedVersion, newVersion)
	}
}
