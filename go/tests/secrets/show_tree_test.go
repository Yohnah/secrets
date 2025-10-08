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

// TestShowTreeValidProfile tests showing tree for a valid profile and environment
func TestShowTreeValidProfile(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Change to tmpDir
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Create secrets.yml with test profile
	secretsYML := `---
metadata:
  profile: "test-tree-profile"
  default_environment: "development"
environments:
  development:
    - name: "DB_HOST"
      type: "envvar"
      entry: "/Development/Database"
      key: "host"
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Development/Database"
      key: "Password"
    - name: "API_KEY"
      type: "envvar"
      entry: "/Development/API/External"
      key: "key"
outputs: {}`

	secretsPath := filepath.Join(tmpDir, "secrets.yml")
	if err := os.WriteFile(secretsPath, []byte(secretsYML), 0644); err != nil {
		t.Fatalf("Failed to create secrets.yml: %v", err)
	}

	// Setup managers following init_test.go pattern
	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, &types.CommandFlags{}, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), validator.NewManager())

	// Initialize database
	err := secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Test show tree command
	err = secretsMgr.ShowTree("test-tree-profile", "development", "ansi")
	if err != nil {
		t.Fatalf("ShowTree failed: %v", err)
	}

	t.Logf("✓ Show tree command executed successfully with ANSI format")
}

// TestShowTreeASCIIFormat tests showing tree with ASCII format
func TestShowTreeASCIIFormat(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Create secrets.yml with test profile
	secretsYML := `---
metadata:
  profile: "ascii-test"
  default_environment: "production"
environments:
  production:
    - name: "SECRET_KEY"
      type: "envvar"
      entry: "/Production/App"
      key: "key"
outputs: {}`

	secretsPath := filepath.Join(tmpDir, "secrets.yml")
	if err := os.WriteFile(secretsPath, []byte(secretsYML), 0644); err != nil {
		t.Fatalf("Failed to create secrets.yml: %v", err)
	}

	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, &types.CommandFlags{}, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Test show tree command with ASCII format
	err = secretsMgr.ShowTree("ascii-test", "production", "ascii")
	if err != nil {
		t.Fatalf("ShowTree with ASCII format failed: %v", err)
	}

	t.Logf("✓ Show tree command executed successfully with ASCII format")
}

// TestShowTreeInvalidProfile tests showing tree for non-existent profile
func TestShowTreeInvalidProfile(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Create secrets.yml with test profile
	secretsYML := `---
metadata:
  profile: "valid-profile"
  default_environment: "development"
environments:
  development:
    - name: "TEST_VAR"
      type: "envvar"
      entry: "/Test"
      key: "key"
outputs: {}`

	secretsPath := filepath.Join(tmpDir, "secrets.yml")
	if err := os.WriteFile(secretsPath, []byte(secretsYML), 0644); err != nil {
		t.Fatalf("Failed to create secrets.yml: %v", err)
	}

	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, &types.CommandFlags{}, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Test show tree command with non-existent profile (should fail)
	err = secretsMgr.ShowTree("nonexistent-profile", "development", "ansi")
	if err == nil {
		t.Fatalf("Expected error for non-existent profile, but got nil")
	}

	if !contains(err.Error(), "nonexistent-profile") && !contains(err.Error(), "profile") && !contains(err.Error(), "not found") {
		t.Logf("Warning: Error message doesn't mention profile issue: %v", err)
	}

	t.Logf("✓ Show tree correctly failed for non-existent profile: %v", err)
}

// TestShowTreeInvalidEnvironment tests showing tree for non-existent environment
func TestShowTreeInvalidEnvironment(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Create secrets.yml with test profile
	secretsYML := `---
metadata:
  profile: "env-test"
  default_environment: "development"
environments:
  development:
    - name: "TEST_VAR"
      type: "envvar"
      entry: "/Test"
      key: "key"
outputs: {}`

	secretsPath := filepath.Join(tmpDir, "secrets.yml")
	if err := os.WriteFile(secretsPath, []byte(secretsYML), 0644); err != nil {
		t.Fatalf("Failed to create secrets.yml: %v", err)
	}

	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, &types.CommandFlags{}, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Test show tree command with non-existent environment (should fail)
	err = secretsMgr.ShowTree("env-test", "nonexistent-env", "ansi")
	if err == nil {
		t.Fatalf("Expected error for non-existent environment, but got nil")
	}

	if !contains(err.Error(), "nonexistent-env") && !contains(err.Error(), "environment") && !contains(err.Error(), "not found") {
		t.Logf("Warning: Error message doesn't mention environment issue: %v", err)
	}

	t.Logf("✓ Show tree correctly failed for non-existent environment: %v", err)
}

// TestShowTreeInvalidFormat tests showing tree with invalid format
func TestShowTreeInvalidFormat(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Create secrets.yml with test profile
	secretsYML := `---
metadata:
  profile: "format-test"
  default_environment: "development"
environments:
  development:
    - name: "TEST_VAR"
      type: "envvar"
      entry: "/Test"
      key: "key"
outputs: {}`

	secretsPath := filepath.Join(tmpDir, "secrets.yml")
	if err := os.WriteFile(secretsPath, []byte(secretsYML), 0644); err != nil {
		t.Fatalf("Failed to create secrets.yml: %v", err)
	}

	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, &types.CommandFlags{}, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Test show tree command with invalid format (should fail)
	err = secretsMgr.ShowTree("format-test", "development", "invalid-format")
	if err == nil {
		t.Fatalf("Expected error for invalid format, but got nil")
	}

	if !contains(err.Error(), "invalid-format") && !contains(err.Error(), "format") {
		t.Logf("Warning: Error message doesn't mention format issue: %v", err)
	}

	t.Logf("✓ Show tree correctly failed for invalid format: %v", err)
}
