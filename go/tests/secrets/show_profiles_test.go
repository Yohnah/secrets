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

// TestShowProfiles_AllProfiles tests showing all profiles
func TestShowProfiles_AllProfiles(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create secrets.yml with multiple profiles
	secretsYMLContent := `metadata:
  profile: "webapp-production"

environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Production/Database/PostgreSQL"
      key: "Password"
    - name: "DB_HOST"
      type: "envvar"
      entry: "/Production/Database/PostgreSQL"
      key: "host"

  staging:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Staging/Database/PostgreSQL"
      key: "Password"

outputs: []
---
metadata:
  profile: "webapp-development"

environments:
  development:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Development/Database/PostgreSQL"
      key: "Password"

outputs: []
---
metadata:
  profile: "mobile-backend"

environments:
  production:
    - name: "API_TOKEN"
      type: "envvar"
      entry: "/Production/API/Token"
      key: "Token"

outputs: []`

	secretsYMLPath := filepath.Join(tmpDir, config.SecretsYMLFilename)
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

	commandFlags := &types.CommandFlags{
		OutputFormat: "table",
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, commandFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), newMockTemplateManager(), validatorMgr)

	// Setup infrastructure first
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Initialize database with profiles
	err = secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Test showing all profiles
	err = secretsMgr.ShowProfiles("all")
	if err != nil {
		t.Errorf("ShowProfiles('all') failed: %v", err)
	}
}

// TestShowProfiles_SpecificProfile tests showing a specific profile
func TestShowProfiles_SpecificProfile(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create secrets.yml with multiple profiles
	secretsYMLContent := `metadata:
  profile: "webapp-production"

environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Production/Database/PostgreSQL"
      key: "Password"

outputs: []
---
metadata:
  profile: "webapp-development"

environments:
  development:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Development/Database/PostgreSQL"
      key: "Password"

outputs: []`

	secretsYMLPath := filepath.Join(tmpDir, config.SecretsYMLFilename)
	if err := os.WriteFile(secretsYMLPath, []byte(secretsYMLContent), 0644); err != nil {
		t.Fatalf("Failed to create secrets.yml: %v", err)
	}

	// Change to tmpDir
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Setup managers with JSON output
	flags := &types.GlobalFlags{
		SecretsFile:      secretsYMLPath,
		IgnoreGitProject: true,
		Force:            true,
	}

	commandFlags := &types.CommandFlags{
		OutputFormat: "json",
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, commandFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), newMockTemplateManager(), validatorMgr)

	// Setup infrastructure first
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Initialize database with profiles
	err = secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Test showing specific profile
	err = secretsMgr.ShowProfiles("webapp-production")
	if err != nil {
		t.Errorf("ShowProfiles('webapp-production') failed: %v", err)
	}
}

// TestShowProfiles_ProfileNotFound tests error handling for non-existent profile
func TestShowProfiles_ProfileNotFound(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create secrets.yml with one profile
	secretsYMLContent := `metadata:
  profile: "webapp-production"

environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Production/Database/PostgreSQL"
      key: "Password"

outputs: []`

	secretsYMLPath := filepath.Join(tmpDir, config.SecretsYMLFilename)
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

	commandFlags := &types.CommandFlags{
		OutputFormat: "table",
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, commandFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), newMockTemplateManager(), validatorMgr)

	// Setup infrastructure first
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Initialize database with profiles
	err = secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Test showing non-existent profile (should fail)
	err = secretsMgr.ShowProfiles("nonexistent-profile")
	if err == nil {
		t.Error("ShowProfiles should have failed for non-existent profile")
	}

	// Verify error message
	expectedError := "profile 'nonexistent-profile' not found in secrets.yml"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}
