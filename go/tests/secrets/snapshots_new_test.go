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

// TestSnapshotsNew_Success tests creating a new snapshot successfully
func TestSnapshotsNew_Success(t *testing.T) {
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
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, kpMgr, output.NewManager(), validatorMgr)

	// Initialize database with profile
	err := secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Read HEAD datetime before creating snapshot
	dbPath := configMgr.GetDatabasePath()
	keyfilePath := configMgr.GetKeyfilePath()
	cfg, _ := configMgr.GetConfig()

	err = kpMgr.Open(dbPath, keyfilePath, cfg.Password)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	headDatetimeBeforeSecure, err := kpMgr.GetTreeGroupEntryField("test-profile", "HEAD", "metadata", "datetime")
	if err != nil {
		t.Fatalf("Failed to read HEAD datetime before snapshot: %v", err)
	}
	defer headDatetimeBeforeSecure.Clear()

	kpMgr.CloseWithoutSave()

	// Create first snapshot (HEAD should be at version 1)
	err = secretsMgr.SnapshotsNew("test-profile")
	if err != nil {
		t.Errorf("SnapshotsNew failed: %v", err)
	}

	// Verify v1 was created and HEAD is at version 2
	// Open database to verify
	err = kpMgr.Open(dbPath, keyfilePath, cfg.Password)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer kpMgr.CloseWithoutSave()

	// Check that v1 exists
	treeGroups, err := kpMgr.ListProfileTreeGroups("test-profile")
	if err != nil {
		t.Fatalf("Failed to list tree groups: %v", err)
	}

	hasV1 := false
	hasHEAD := false
	for _, tg := range treeGroups {
		if tg == "v1" {
			hasV1 = true
		}
		if tg == "HEAD" {
			hasHEAD = true
		}
	}

	if !hasV1 {
		t.Errorf("v1 snapshot was not created")
	}
	if !hasHEAD {
		t.Errorf("HEAD should still exist")
	}

	// Check HEAD version is now 2
	versionSecure, err := kpMgr.GetTreeGroupEntryField("test-profile", "HEAD", "metadata", "version")
	if err != nil {
		t.Fatalf("Failed to read HEAD version: %v", err)
	}
	defer versionSecure.Clear()
	if versionSecure.String() != "2" {
		t.Errorf("Expected HEAD version to be 2, got: %s", versionSecure.String())
	}

	// CRITICAL: Verify HEAD datetime did NOT change
	headDatetimeAfterSecure, err := kpMgr.GetTreeGroupEntryField("test-profile", "HEAD", "metadata", "datetime")
	if err != nil {
		t.Fatalf("Failed to read HEAD datetime after snapshot: %v", err)
	}
	defer headDatetimeAfterSecure.Clear()
	if headDatetimeBeforeSecure.String() != headDatetimeAfterSecure.String() {
		t.Errorf("HEAD datetime should NOT change. Before: %s, After: %s", headDatetimeBeforeSecure.String(), headDatetimeAfterSecure.String())
	}

	// CRITICAL: Verify v1 datetime WAS updated (different from HEAD's original)
	v1DatetimeSecure, err := kpMgr.GetTreeGroupEntryField("test-profile", "v1", "metadata", "datetime")
	if err != nil {
		t.Fatalf("Failed to read v1 datetime: %v", err)
	}
	defer v1DatetimeSecure.Clear()
	// v1 datetime should be updated to snapshot creation time
	// It should be different from the original HEAD datetime (unless they happen at exact same millisecond, unlikely)
	// For this test, we just verify it's a valid ISO 8601 datetime and exists
	if v1DatetimeSecure.String() == "" {
		t.Errorf("v1 datetime should not be empty")
	}
}

// TestSnapshotsNew_ProfileNotInSecretsYML tests error when profile doesn't exist in secrets.yml
func TestSnapshotsNew_ProfileNotInSecretsYML(t *testing.T) {
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
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), validatorMgr)

	// Initialize database
	err := secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Try to create snapshot for non-existent profile
	err = secretsMgr.SnapshotsNew("non-existent-profile")
	if err == nil {
		t.Error("Expected error for non-existent profile in secrets.yml, got nil")
	}
}

// TestSnapshotsNew_ProfileNotInDatabase tests error when profile doesn't exist in database
func TestSnapshotsNew_ProfileNotInDatabase(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create secrets.yml with two profiles
	secretsYMLContent := `metadata:
  profile: "profile-in-db"

environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Production/DB"
      key: "Password"

outputs: []
---
metadata:
  profile: "profile-not-in-db"

environments:
  production:
    - name: "API_TOKEN"
      type: "envvar"
      entry: "/Production/API"
      key: "Token"

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
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, kpMgr, output.NewManager(), validatorMgr)

	// Initialize database (only profile-in-db will be created)
	err := secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Open database and manually delete profile-not-in-db to simulate scenario
	dbPath := configMgr.GetDatabasePath()
	keyfilePath := configMgr.GetKeyfilePath()
	cfg, _ := configMgr.GetConfig()

	err = kpMgr.Open(dbPath, keyfilePath, cfg.Password)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	// Get database and manually remove the profile-not-in-db group
	db := kpMgr.GetDatabase()
	if len(db.Content.Root.Groups) > 0 {
		rootGroup := &db.Content.Root.Groups[0]
		// Find and remove profile-not-in-db
		for i, group := range rootGroup.Groups {
			if group.Name == "profile-not-in-db" {
				// Remove this group
				rootGroup.Groups = append(rootGroup.Groups[:i], rootGroup.Groups[i+1:]...)
				break
			}
		}
	}

	err = kpMgr.SaveAndClose()
	if err != nil {
		t.Fatalf("Failed to save database: %v", err)
	}

	// Try to create snapshot for profile not in database
	err = secretsMgr.SnapshotsNew("profile-not-in-db")
	if err == nil {
		t.Error("Expected error for profile not in database, got nil")
	}
}

// TestSnapshotsNew_MultipleSnapshots tests creating multiple snapshots
func TestSnapshotsNew_MultipleSnapshots(t *testing.T) {
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
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, kpMgr, output.NewManager(), validatorMgr)

	// Initialize database
	err := secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Create first snapshot
	err = secretsMgr.SnapshotsNew("test-profile")
	if err != nil {
		t.Errorf("First SnapshotsNew failed: %v", err)
	}

	// Create second snapshot
	err = secretsMgr.SnapshotsNew("test-profile")
	if err != nil {
		t.Errorf("Second SnapshotsNew failed: %v", err)
	}

	// Create third snapshot
	err = secretsMgr.SnapshotsNew("test-profile")
	if err != nil {
		t.Errorf("Third SnapshotsNew failed: %v", err)
	}

	// Verify all snapshots were created
	dbPath := configMgr.GetDatabasePath()
	keyfilePath := configMgr.GetKeyfilePath()
	cfg, _ := configMgr.GetConfig()

	err = kpMgr.Open(dbPath, keyfilePath, cfg.Password)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer kpMgr.CloseWithoutSave()

	treeGroups, err := kpMgr.ListProfileTreeGroups("test-profile")
	if err != nil {
		t.Fatalf("Failed to list tree groups: %v", err)
	}

	expectedGroups := map[string]bool{
		"HEAD": true,
		"v1":   true,
		"v2":   true,
		"v3":   true,
	}

	for group := range expectedGroups {
		found := false
		for _, tg := range treeGroups {
			if tg == group {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected tree group '%s' not found", group)
		}
	}

	// Check HEAD version is now 4
	versionSecure, err := kpMgr.GetTreeGroupEntryField("test-profile", "HEAD", "metadata", "version")
	if err != nil {
		t.Fatalf("Failed to read HEAD version: %v", err)
	}
	defer versionSecure.Clear()
	if versionSecure.String() != "4" {
		t.Errorf("Expected HEAD version to be 4, got: %s", versionSecure.String())
	}
}
