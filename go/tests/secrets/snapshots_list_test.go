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

// TestSnapshotsList_AllProfiles tests listing all snapshots
func TestSnapshotsList_AllProfiles(t *testing.T) {
tmpDir := setupTestDir(t)
setupTestPassword(t)
initGitRepo(t, tmpDir)

// Create secrets.yml with multiple profiles
secretsYMLContent := `metadata:
  profile: "webapp-production"
  default_environment: "production"

environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Production/DB"
      key: "Password"

outputs: {}
---
metadata:
  profile: "webapp-development"
  default_environment: "development"

environments:
  development:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Development/DB"
      key: "Password"

outputs: {}
---
metadata:
  profile: "mobile-backend"
  default_environment: "production"

environments:
  production:
    - name: "API_TOKEN"
      type: "envvar"
      entry: "/Production/API"
      key: "Token"

outputs: {}`

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
OutputFormat: "table",
}

validatorMgr := validator.NewManager()
configMgr := config.NewManager(flags, commandFlags, validatorMgr)
loggerMgr := logger.NewManager(false)
promptMgr := prompt.NewManager()
secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validatorMgr)

// Initialize database with profiles
err := secretsMgr.Init()
if err != nil {
t.Fatalf("Init failed: %v", err)
}

// Test listing all profiles
err = secretsMgr.SnapshotsList("all")
if err != nil {
t.Errorf("SnapshotsList('all') failed: %v", err)
}
}

// TestSnapshotsList_SpecificProfile tests listing snapshots for a specific profile
func TestSnapshotsList_SpecificProfile(t *testing.T) {
tmpDir := setupTestDir(t)
setupTestPassword(t)
initGitRepo(t, tmpDir)

// Create secrets.yml with multiple profiles
secretsYMLContent := `metadata:
  profile: "webapp-production"
  default_environment: "production"

environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Production/DB"
      key: "Password"

outputs: {}
---
metadata:
  profile: "webapp-development"
  default_environment: "development"

environments:
  development:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Development/DB"
      key: "Password"

outputs: {}`

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
secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validatorMgr)

// Initialize database with profiles
err := secretsMgr.Init()
if err != nil {
t.Fatalf("Init failed: %v", err)
}

// Test listing specific profile
err = secretsMgr.SnapshotsList("webapp-production")
if err != nil {
t.Errorf("SnapshotsList('webapp-production') failed: %v", err)
}
}

// TestSnapshotsList_InvalidProfile tests error handling for non-existent profile
func TestSnapshotsList_InvalidProfile(t *testing.T) {
tmpDir := setupTestDir(t)
setupTestPassword(t)
initGitRepo(t, tmpDir)

// Create secrets.yml with one profile
secretsYMLContent := `metadata:
  profile: "webapp-production"
  default_environment: "production"

environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Production/DB"
      key: "Password"

outputs: {}`

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
OutputFormat: "table",
}

validatorMgr := validator.NewManager()
configMgr := config.NewManager(flags, commandFlags, validatorMgr)
loggerMgr := logger.NewManager(false)
promptMgr := prompt.NewManager()
secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validatorMgr)

// Initialize database with profiles
err := secretsMgr.Init()
if err != nil {
t.Fatalf("Init failed: %v", err)
}

// Test listing non-existent profile - should fail
err = secretsMgr.SnapshotsList("non-existent-profile")
if err == nil {
t.Error("SnapshotsList('non-existent-profile') should have failed but didn't")
}
}

// TestSnapshotsList_OutputFormats tests different output formats
func TestSnapshotsList_OutputFormats(t *testing.T) {
tmpDir := setupTestDir(t)
setupTestPassword(t)
initGitRepo(t, tmpDir)

// Create secrets.yml with one profile
secretsYMLContent := `metadata:
  profile: "webapp-production"
  default_environment: "production"

environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Production/DB"
      key: "Password"

outputs: {}`

secretsYMLPath := filepath.Join(tmpDir, "secrets.yml")
if err := os.WriteFile(secretsYMLPath, []byte(secretsYMLContent), 0644); err != nil {
t.Fatalf("Failed to create secrets.yml: %v", err)
}

// Change to tmpDir
originalDir, _ := os.Getwd()
defer os.Chdir(originalDir)
os.Chdir(tmpDir)

// Test different output formats
formats := []string{"table", "json", "yaml"}

for _, format := range formats {
t.Run("format_"+format, func(t *testing.T) {
// Setup managers
flags := &types.GlobalFlags{
SecretsFile:      secretsYMLPath,
IgnoreGitProject: true,
Force:            true,
}

commandFlags := &types.CommandFlags{
OutputFormat: format,
}

validatorMgr := validator.NewManager()
configMgr := config.NewManager(flags, commandFlags, validatorMgr)
loggerMgr := logger.NewManager(false)
promptMgr := prompt.NewManager()
secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validatorMgr)

// Initialize database with profiles
err := secretsMgr.Init()
if err != nil {
t.Fatalf("Init failed: %v", err)
}

// Test listing with specific format
err = secretsMgr.SnapshotsList("webapp-production")
if err != nil {
t.Errorf("SnapshotsList with format '%s' failed: %v", format, err)
}
})
}
}
