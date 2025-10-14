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

// TestSnapshotsDelete_Success tests deleting a snapshot successfully
func TestSnapshotsDelete_Success(t *testing.T) {
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

	// Setup mock KeePass manager with snapshots
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
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKP, output.NewManager(), newMockTemplateManager(), validatorMgr)

	// Verify v1 and v2 exist before deletion
	v1Exists, _ := mockKP.TreeGroupExists("test-profile", "v1")
	v2Exists, _ := mockKP.TreeGroupExists("test-profile", "v2")

	if !v1Exists {
		t.Fatalf("v1 does not exist before deletion")
	}
	if !v2Exists {
		t.Fatalf("v2 does not exist before deletion")
	}

	// Delete v1
	err := secretsMgr.SnapshotsDelete("test-profile", "v1")
	if err != nil {
		t.Errorf("SnapshotsDelete failed: %v", err)
	}

	// Verify v1 was deleted but v2 and HEAD still exist
	v1ExistsAfter, _ := mockKP.TreeGroupExists("test-profile", "v1")
	v2ExistsAfter, _ := mockKP.TreeGroupExists("test-profile", "v2")
	headExistsAfter, _ := mockKP.TreeGroupExists("test-profile", "HEAD")

	if v1ExistsAfter {
		t.Errorf("v1 still exists after deletion")
	}
	if !v2ExistsAfter {
		t.Errorf("v2 was deleted unexpectedly")
	}
	if !headExistsAfter {
		t.Errorf("HEAD was deleted unexpectedly")
	}

	// Verify SaveAndClose was called
	if !mockKP.saveAndCloseCalled {
		t.Errorf("Expected SaveAndClose to be called")
	}
}

// TestSnapshotsDelete_ProfileNotInSecretsYML tests error when profile not in secrets.yml
func TestSnapshotsDelete_ProfileNotInSecretsYML(t *testing.T) {
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
	kpMgr := newMockKeePassManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, kpMgr, output.NewManager(), newMockTemplateManager(), validatorMgr)

	// Try to delete from non-existent profile
	err := secretsMgr.SnapshotsDelete("non-existent-profile", "v1")
	if err == nil {
		t.Errorf("Expected error when profile not in secrets.yml, got nil")
	}
}

// TestSnapshotsDelete_CannotDeleteHEAD tests error when trying to delete HEAD
func TestSnapshotsDelete_CannotDeleteHEAD(t *testing.T) {
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
	kpMgr := newMockKeePassManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, kpMgr, output.NewManager(), newMockTemplateManager(), validatorMgr)

	// Setup infrastructure first
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Initialize database with profile
	err = secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Try to delete HEAD
	err = secretsMgr.SnapshotsDelete("test-profile", "HEAD")
	if err == nil {
		t.Errorf("Expected error when trying to delete HEAD, got nil")
	}
}

// TestSnapshotsDelete_VersionNotFound tests error when version does not exist
func TestSnapshotsDelete_VersionNotFound(t *testing.T) {
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
	kpMgr := newMockKeePassManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, kpMgr, output.NewManager(), newMockTemplateManager(), validatorMgr)

	// Setup infrastructure first
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Initialize database with profile
	err = secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Try to delete non-existent version
	err = secretsMgr.SnapshotsDelete("test-profile", "v999")
	if err == nil {
		t.Errorf("Expected error when version does not exist, got nil")
	}
}

// TestSnapshotsDelete_InvalidVersionFormat tests error for invalid version format
func TestSnapshotsDelete_InvalidVersionFormat(t *testing.T) {
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
	kpMgr := newMockKeePassManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, kpMgr, output.NewManager(), newMockTemplateManager(), validatorMgr)

	// Test various invalid version formats
	testCases := []string{
		"1",        // Missing 'v'
		"version1", // Wrong format
		"v-1",      // Negative
		"v0",       // Zero
		"vabc",     // Non-numeric
	}

	for _, version := range testCases {
		err := secretsMgr.SnapshotsDelete("test-profile", version)
		if err == nil {
			t.Errorf("Expected error for invalid version format '%s', got nil", version)
		}
	}
}
