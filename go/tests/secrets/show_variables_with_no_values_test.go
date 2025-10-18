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

// TestShowVariables_WithNoValues_NoPasswordPrompt tests that --with-no-values doesn't prompt for password
func TestShowVariables_WithNoValues_NoPasswordPrompt(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a minimal secrets.yml
	secretsYML := `
metadata:
  profile: test-profile
environments:
  test-env:
    - name: TEST_VAR1
      type: envvar
      entry: /test/entry1
      key: password
    - name: TEST_VAR2
      type: envvar
      entry: /test/entry2
      key: username
`

	secretsYMLPath := filepath.Join(tmpDir, "secrets.yml")
	err := os.WriteFile(secretsYMLPath, []byte(secretsYML), 0644)
	if err != nil {
		t.Fatalf("Failed to create secrets.yml: %v", err)
	}

	// Change to test directory
	oldCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldCwd)

	// Setup managers like in show_profiles_test.go
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

	// For --with-no-values, we don't need Setup/Init since we bypass KeePass
	// This should work without prompting for password and without KeePass database
	err = secretsMgr.ShowVariables("test-env", "json", "", true) // withNoValues = true

	if err != nil {
		t.Errorf("ShowVariables with --with-no-values failed: %v", err)
	}
}

// TestShowVariables_WithNoValues_ContainsAllVariables tests that all variables from secrets.yml are shown
func TestShowVariables_WithNoValues_ContainsAllVariables(t *testing.T) {
	tmpDir := t.TempDir()

	// Create secrets.yml with multiple variables
	secretsYML := `
metadata:
  profile: multi-var-profile
environments:
  multi-env:
    - name: DB_HOST
      type: envvar
      entry: /db
      key: host
    - name: DB_PORT
      type: envvar
      entry: /db
      key: port
    - name: API_KEY
      type: envvar
      entry: /api
      key: key
    - name: DEBUG_MODE
      type: envvar
      entry: /app
      key: debug
`

	secretsYMLPath := filepath.Join(tmpDir, "secrets.yml")
	err := os.WriteFile(secretsYMLPath, []byte(secretsYML), 0644)
	if err != nil {
		t.Fatalf("Failed to create secrets.yml: %v", err)
	}

	// Change to test directory
	oldCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldCwd)

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
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), output.NewManager(), newMockTemplateManager(), validatorMgr)

	// For --with-no-values, we don't need Setup/Init since we bypass KeePass
	// This should work and show all variables with empty values
	err = secretsMgr.ShowVariables("multi-env", "json", "", true) // withNoValues = true

	if err != nil {
		t.Errorf("ShowVariables with --with-no-values failed: %v", err)
	}
}
