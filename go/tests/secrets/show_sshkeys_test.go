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

// TestShowSSHKeys_Success tests listing SSH keys successfully
func TestShowSSHKeys_Success(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create secrets.yml with SSH keys
	secretsYMLContent := `metadata:
  profile: "webapp-production"

environments:
  production:
    - name: "DB_HOST"
      type: "sshkey"
      entry: "/Database/PostgreSQL"
      key: "attachments/id_rsa"
    - name: "DB_HOST10"
      type: "sshkey"
      entry: "/Database/PostgreSQL10"
      key: "attachments/id_rsa"
    - name: "API_TOKEN"
      type: "envvar"
      entry: "/API/Token"
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

	commandFlags := &types.CommandFlags{
		OutputFormat: "json",
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, commandFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	mockKeePass := newMockKeePassManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKeePass, output.NewManager(), newMockTemplateManager(), validatorMgr)

	// Setup infrastructure first
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Test ShowSSHKeys
	err = secretsMgr.ShowSSHKeys("production", "json")
	if err != nil {
		t.Errorf("ShowSSHKeys failed: %v", err)
	}

	// Note: In a real implementation, we would capture stdout to verify the output
	// For this test, we're verifying that no error is returned
}

// TestShowSSHKeys_EnvironmentNotFound tests error when environment doesn't exist
func TestShowSSHKeys_EnvironmentNotFound(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create secrets.yml
	secretsYMLContent := `metadata:
  profile: "webapp-production"

environments:
  production:
    - name: "DB_HOST"
      type: "sshkey"
      entry: "/Database/PostgreSQL"
      key: "attachments/id_rsa"

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

	commandFlags := &types.CommandFlags{
		OutputFormat: "json",
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, commandFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	mockKeePass := newMockKeePassManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKeePass, output.NewManager(), newMockTemplateManager(), validatorMgr)

	// Setup infrastructure
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Test ShowSSHKeys with non-existent environment
	err = secretsMgr.ShowSSHKeys("nonexistent", "json")
	if err == nil {
		t.Error("Expected error for non-existent environment, got nil")
	}

	expectedErrMsg := "environment 'nonexistent' does not exist"
	if err != nil && !contains(err.Error(), expectedErrMsg) {
		t.Errorf("Expected error containing '%s', got: %v", expectedErrMsg, err)
	}
}

// TestShowSSHKeys_NoSSHKeys tests error when no SSH keys exist
func TestShowSSHKeys_NoSSHKeys(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create secrets.yml with only envvar items
	secretsYMLContent := `metadata:
  profile: "webapp-production"

environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Database/PostgreSQL"
      key: "Password"
    - name: "API_TOKEN"
      type: "envvar"
      entry: "/API/Token"
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

	commandFlags := &types.CommandFlags{
		OutputFormat: "json",
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, commandFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	mockKeePass := newMockKeePassManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKeePass, output.NewManager(), newMockTemplateManager(), validatorMgr)

	// Setup infrastructure
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Test ShowSSHKeys when no SSH keys exist
	err = secretsMgr.ShowSSHKeys("production", "json")
	if err == nil {
		t.Error("Expected error when no SSH keys exist, got nil")
	}

	expectedErrMsg := "no SSH keys (type=sshkey) found"
	if err != nil && !contains(err.Error(), expectedErrMsg) {
		t.Errorf("Expected error containing '%s', got: %v", expectedErrMsg, err)
	}
}

// TestShowSSHKeys_MultipleProfiles tests auto-detect failure with multiple profiles
func TestShowSSHKeys_MultipleProfiles(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create secrets.yml with multiple profiles
	secretsYMLContent := `metadata:
  profile: "webapp-production"

environments:
  production:
    - name: "DB_HOST"
      type: "sshkey"
      entry: "/Database/PostgreSQL"
      key: "attachments/id_rsa"

outputs: []
---
metadata:
  profile: "mobile-backend"

environments:
  production:
    - name: "API_KEY"
      type: "sshkey"
      entry: "/API/Key"
      key: "attachments/api_key"

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

	commandFlags := &types.CommandFlags{
		OutputFormat: "json",
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, commandFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	mockKeePass := newMockKeePassManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKeePass, output.NewManager(), newMockTemplateManager(), validatorMgr)

	// Setup infrastructure
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Test ShowSSHKeys with multiple profiles (should fail auto-detect)
	err = secretsMgr.ShowSSHKeys("production", "json")
	if err == nil {
		t.Error("Expected error for multiple profiles without --profile-name, got nil")
	}

	expectedErrMsg := "multiple profiles found"
	if err != nil && !contains(err.Error(), expectedErrMsg) {
		t.Errorf("Expected error containing '%s', got: %v", expectedErrMsg, err)
	}
}

// TestShowSSHKeyContent_Success tests retrieving SSH key content successfully
func TestShowSSHKeyContent_Success(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create secrets.yml with SSH key
	secretsYMLContent := `metadata:
  profile: "webapp-production"

environments:
  production:
    - name: "DB_HOST"
      type: "sshkey"
      entry: "/Database/PostgreSQL"
      key: "attachments/id_rsa"

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
	mockKeePass := newMockKeePassManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKeePass, output.NewManager(), newMockTemplateManager(), validatorMgr)

	// Setup infrastructure
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Initialize database
	err = secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Test ShowSSHKeyContent
	err = secretsMgr.ShowSSHKeyContent("production", "DB_HOST")
	if err != nil {
		t.Errorf("ShowSSHKeyContent failed: %v", err)
	}

	// Note: In a real implementation, we would capture stdout to verify the output
	// For this test, we're verifying that no error is returned
}

// TestShowSSHKeyContent_ItemNotFound tests error when item doesn't exist
func TestShowSSHKeyContent_ItemNotFound(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create secrets.yml
	secretsYMLContent := `metadata:
  profile: "webapp-production"

environments:
  production:
    - name: "DB_HOST"
      type: "sshkey"
      entry: "/Database/PostgreSQL"
      key: "attachments/id_rsa"

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
	mockKeePass := newMockKeePassManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKeePass, output.NewManager(), newMockTemplateManager(), validatorMgr)

	// Setup infrastructure
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Initialize database
	err = secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Test ShowSSHKeyContent with non-existent item
	err = secretsMgr.ShowSSHKeyContent("production", "NONEXISTENT")
	if err == nil {
		t.Error("Expected error for non-existent item, got nil")
	}

	expectedErrMsg := "item 'NONEXISTENT' not found"
	if err != nil && !contains(err.Error(), expectedErrMsg) {
		t.Errorf("Expected error containing '%s', got: %v", expectedErrMsg, err)
	}
}

// TestShowSSHKeyContent_WrongType tests error when item is not sshkey type
func TestShowSSHKeyContent_WrongType(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create secrets.yml with envvar instead of sshkey
	secretsYMLContent := `metadata:
  profile: "webapp-production"

environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Database/PostgreSQL"
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
	mockKeePass := newMockKeePassManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKeePass, output.NewManager(), newMockTemplateManager(), validatorMgr)

	// Setup infrastructure
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Initialize database
	err = secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Test ShowSSHKeyContent with wrong type
	err = secretsMgr.ShowSSHKeyContent("production", "DB_PASSWORD")
	if err == nil {
		t.Error("Expected error for wrong item type, got nil")
	}

	expectedErrMsg := "is not of type 'sshkey'"
	if err != nil && !contains(err.Error(), expectedErrMsg) {
		t.Errorf("Expected error containing '%s', got: %v", expectedErrMsg, err)
	}
}

// TestShowSSHKeyContent_NotAttachment tests error when key is not an attachment
func TestShowSSHKeyContent_NotAttachment(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create secrets.yml with sshkey but key is not attachment
	secretsYMLContent := `metadata:
  profile: "webapp-production"

environments:
  production:
    - name: "DB_HOST"
      type: "sshkey"
      entry: "/Database/PostgreSQL"
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
	mockKeePass := newMockKeePassManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKeePass, output.NewManager(), newMockTemplateManager(), validatorMgr)

	// Setup infrastructure
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Initialize database
	err = secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Test ShowSSHKeyContent when key is not an attachment
	err = secretsMgr.ShowSSHKeyContent("production", "DB_HOST")
	if err == nil {
		t.Error("Expected error for non-attachment key, got nil")
	}

	expectedErrMsg := "does not reference an attachment"
	if err != nil && !contains(err.Error(), expectedErrMsg) {
		t.Errorf("Expected error containing '%s', got: %v", expectedErrMsg, err)
	}
}

// TestShowSSHKeyContent_EnvironmentNotFound tests error when environment doesn't exist
func TestShowSSHKeyContent_EnvironmentNotFound(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create secrets.yml
	secretsYMLContent := `metadata:
  profile: "webapp-production"

environments:
  production:
    - name: "DB_HOST"
      type: "sshkey"
      entry: "/Database/PostgreSQL"
      key: "attachments/id_rsa"

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
	mockKeePass := newMockKeePassManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, mockKeePass, output.NewManager(), newMockTemplateManager(), validatorMgr)

	// Setup infrastructure
	err := secretsMgr.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Initialize database
	err = secretsMgr.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Test ShowSSHKeyContent with non-existent environment
	err = secretsMgr.ShowSSHKeyContent("staging", "DB_HOST")
	if err == nil {
		t.Error("Expected error for non-existent environment, got nil")
	}

	expectedErrMsg := "environment 'staging' does not exist"
	if err != nil && !contains(err.Error(), expectedErrMsg) {
		t.Errorf("Expected error containing '%s', got: %v", expectedErrMsg, err)
	}
}
