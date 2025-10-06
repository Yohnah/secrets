package secrets_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/validator"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/output"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/Yohnah/secrets/internal/secrets/initialize"
	"github.com/Yohnah/secrets/internal/types"
)

// setupTestDir creates a temporary test directory
func setupTestDir(t *testing.T) string {
	tmpDir, err := os.MkdirTemp("", "secrets-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})
	return tmpDir
}

// setupTestPassword sets up the password environment variable for tests
// and ensures it's cleaned up after the test completes
func setupTestPassword(t *testing.T) {
	testPassword := "test-password-123"
	os.Setenv("SECRETS_YOHNAH_PASSWORD", testPassword)
	t.Cleanup(func() {
		os.Unsetenv("SECRETS_YOHNAH_PASSWORD")
	})
}

// initGitRepo initializes a git repository in the given directory
func initGitRepo(t *testing.T, dir string) {
	gitDir := filepath.Join(dir, ".git")
	if err := os.Mkdir(gitDir, 0755); err != nil {
		t.Fatalf("Failed to create .git directory: %v", err)
	}
}

// TestInitCreatesSecretsYohnahDirectory tests that init creates .secrets_yohnah directory
func TestInitCreatesSecretsYohnahDirectory(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Change to tmpDir
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Setup managers
	flags := &types.GlobalFlags{
		Force: true, // Non-interactive mode
	}

	validatorMgr := validator.NewManager()

	configMgr := config.NewManager(flags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validator.NewManager())

	// Execute init
	err := secretsMgr.Init(initialize.Options{})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify .secrets_yohnah was created
	secretsDir := filepath.Join(tmpDir, ".secrets_yohnah")
	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		t.Errorf(".secrets_yohnah directory was not created")
	}
}

// TestInitCreatesConfigYml tests that init creates config.yml file
func TestInitCreatesConfigYml(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()

	configMgr := config.NewManager(flags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr.Init(initialize.Options{})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify config.yml was created
	configFile := filepath.Join(tmpDir, ".secrets_yohnah", "config.yml")
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		t.Errorf("config.yml was not created")
	}

	// Verify config.yml content
	content, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to read config.yml: %v", err)
	}

	contentStr := string(content)
	if !contains(contentStr, "database:") {
		t.Errorf("config.yml does not contain 'database:' field")
	}
	if !contains(contentStr, "keyfile:") {
		t.Errorf("config.yml does not contain 'keyfile:' field")
	}
}

// TestInitWithIgnoreConfigFile tests that init with --ignore-config-file creates database but not config.yml
func TestInitWithIgnoreConfigFile(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	flags := &types.GlobalFlags{
		Force:            true,
		IgnoreConfigFile: true,
	}

	validatorMgr := validator.NewManager()

	configMgr := config.NewManager(flags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr.Init(initialize.Options{})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify .secrets_yohnah directory WAS created
	secretsDir := filepath.Join(tmpDir, ".secrets_yohnah")
	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		t.Errorf(".secrets_yohnah directory should have been created")
	}

	// Verify database WAS created
	dbPath := filepath.Join(tmpDir, ".secrets_yohnah", "secrets.kdbx")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("Database should have been created")
	}

	// Verify keyfile WAS created
	keyfilePath := filepath.Join(tmpDir, ".secrets_yohnah", "secrets.keyfile")
	if _, err := os.Stat(keyfilePath); os.IsNotExist(err) {
		t.Errorf("Keyfile should have been created")
	}

	// Verify config.yml was NOT created (--ignore-config-file)
	configPath := filepath.Join(secretsDir, "config.yml")
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Errorf("config.yml should NOT have been created with --ignore-config-file")
	}
}

// TestInitWithIgnoreGitProject tests that init with --ignore-git-project creates in current directory
func TestInitWithIgnoreGitProject(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	// Don't create .git directory

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	flags := &types.GlobalFlags{
		Force:            true,
		IgnoreGitProject: true,
	}

	validatorMgr := validator.NewManager()

	configMgr := config.NewManager(flags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr.Init(initialize.Options{})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify .secrets_yohnah was created in current directory
	secretsDir := filepath.Join(tmpDir, ".secrets_yohnah")
	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		t.Errorf(".secrets_yohnah directory was not created in current directory")
	}
}

// TestInitWithoutGitFails tests that init without git and without --ignore-git-project fails
func TestInitWithoutGitFails(t *testing.T) {
	tmpDir := setupTestDir(t)
	// Don't create .git directory

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()

	configMgr := config.NewManager(flags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr.Init(initialize.Options{})
	if err == nil {
		t.Errorf("Init should have failed without git repository and without --ignore-git-project")
	}
}

// TestInitDoesNotOverwriteExistingConfig tests that existing config.yml is not overwritten
// and that existing database/keyfile are verified instead of recreated
func TestInitDoesNotOverwriteExistingConfig(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// First, run init normally to create everything
	flags1 := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()

	configMgr1 := config.NewManager(flags1, validatorMgr)
	loggerMgr1 := logger.NewManager(false)
	promptMgr1 := prompt.NewManager()
	secretsMgr1 := secrets.NewManager(configMgr1, loggerMgr1, promptMgr1, keepass.NewManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr1.Init(initialize.Options{})
	if err != nil {
		t.Fatalf("First init failed: %v", err)
	}

	// Read the config.yml content
	configFile := filepath.Join(tmpDir, ".secrets_yohnah", "config.yml")
	originalContent, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to read config.yml: %v", err)
	}

	// Get modification time of database and keyfile
	dbPath := filepath.Join(tmpDir, ".secrets_yohnah", "secrets.kdbx")
	keyfilePath := filepath.Join(tmpDir, ".secrets_yohnah", "secrets.keyfile")

	dbInfo, _ := os.Stat(dbPath)
	keyInfo, _ := os.Stat(keyfilePath)
	originalDbModTime := dbInfo.ModTime()
	originalKeyModTime := keyInfo.ModTime()

	// Run init again - should verify, not recreate
	flags2 := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr = validator.NewManager()

	configMgr2 := config.NewManager(flags2, validatorMgr)
	loggerMgr2 := logger.NewManager(false)
	promptMgr2 := prompt.NewManager()
	secretsMgr2 := secrets.NewManager(configMgr2, loggerMgr2, promptMgr2, keepass.NewManager(), output.NewManager(), validator.NewManager())

	err = secretsMgr2.Init(initialize.Options{})
	if err != nil {
		t.Fatalf("Second init failed: %v", err)
	}

	// Verify config.yml was not modified
	newContent, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to read config.yml after second init: %v", err)
	}

	if string(newContent) != string(originalContent) {
		t.Errorf("config.yml was modified on second init")
	}

	// Verify database and keyfile were not recreated (modification time unchanged)
	dbInfo2, _ := os.Stat(dbPath)
	keyInfo2, _ := os.Stat(keyfilePath)

	if !dbInfo2.ModTime().Equal(originalDbModTime) {
		t.Errorf("Database was recreated on second init")
	}

	if !keyInfo2.ModTime().Equal(originalKeyModTime) {
		t.Errorf("Keyfile was recreated on second init")
	}
} // TestInitWithCustomPaths tests that init uses custom paths from flags
func TestInitWithCustomPaths(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Create directories for custom paths
	customDir := filepath.Join(tmpDir, "custom")
	os.MkdirAll(customDir, 0755)

	flags := &types.GlobalFlags{
		Force:    true,
		Database: filepath.Join(customDir, "db.kdbx"),
		Keyfile:  filepath.Join(customDir, "key.file"),
	}

	validatorMgr := validator.NewManager()

	configMgr := config.NewManager(flags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr.Init(initialize.Options{})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify config.yml contains custom paths
	configFile := filepath.Join(tmpDir, ".secrets_yohnah", "config.yml")
	content, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to read config.yml: %v", err)
	}

	contentStr := string(content)
	if !contains(contentStr, "/custom/db.kdbx") {
		t.Errorf("config.yml does not contain custom database path")
	}
	if !contains(contentStr, "/custom/key.file") {
		t.Errorf("config.yml does not contain custom keyfile path")
	}
}

// TestInitFindsGitRootFromSubdirectory tests that init finds git root from a subdirectory
func TestInitFindsGitRootFromSubdirectory(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	// Create a subdirectory
	subDir := filepath.Join(tmpDir, "subdir1", "subdir2")
	os.MkdirAll(subDir, 0755)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(subDir)

	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()

	configMgr := config.NewManager(flags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr.Init(initialize.Options{})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify .secrets_yohnah was created in git root, not in subdirectory
	secretsDir := filepath.Join(tmpDir, ".secrets_yohnah")
	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		t.Errorf(".secrets_yohnah directory was not created in git root")
	}

	// Verify it was NOT created in subdirectory
	secretsDirSub := filepath.Join(subDir, ".secrets_yohnah")
	if _, err := os.Stat(secretsDirSub); !os.IsNotExist(err) {
		t.Errorf(".secrets_yohnah directory should not have been created in subdirectory")
	}
}

// TestInitAddsToGitignore tests that init adds .secrets_yohnah to .gitignore
func TestInitAddsToGitignore(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Create existing .gitignore with some content
	existingGitignore := "*.log\nnode_modules/\n"
	gitignorePath := filepath.Join(tmpDir, ".gitignore")
	os.WriteFile(gitignorePath, []byte(existingGitignore), 0644)

	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr.Init(initialize.Options{})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Read .gitignore and verify .secrets_yohnah was added
	content, err := os.ReadFile(gitignorePath)
	if err != nil {
		t.Fatalf("Failed to read .gitignore: %v", err)
	}

	gitignoreContent := string(content)
	if !contains(gitignoreContent, ".secrets_yohnah") {
		t.Errorf(".secrets_yohnah was not added to .gitignore. Content:\n%s", gitignoreContent)
	}

	// Verify existing content is preserved
	if !contains(gitignoreContent, "*.log") {
		t.Errorf("Existing .gitignore content was lost")
	}
}

// TestInitCreatesGitignoreIfNotExists tests that init creates .gitignore if it doesn't exist
func TestInitCreatesGitignoreIfNotExists(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Ensure .gitignore doesn't exist
	gitignorePath := filepath.Join(tmpDir, ".gitignore")
	os.Remove(gitignorePath)

	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr.Init(initialize.Options{})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify .gitignore was created
	if _, err := os.Stat(gitignorePath); os.IsNotExist(err) {
		t.Error(".gitignore was not created")
	}

	// Read .gitignore and verify .secrets_yohnah is there
	content, err := os.ReadFile(gitignorePath)
	if err != nil {
		t.Fatalf("Failed to read .gitignore: %v", err)
	}

	gitignoreContent := string(content)
	if !contains(gitignoreContent, ".secrets_yohnah") {
		t.Errorf(".secrets_yohnah was not added to .gitignore. Content:\n%s", gitignoreContent)
	}
}

// TestInitDoesNotDuplicateGitignoreEntry tests that .secrets_yohnah is not added twice
func TestInitDoesNotDuplicateGitignoreEntry(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Create .gitignore with .secrets_yohnah already present
	existingGitignore := "*.log\n.secrets_yohnah\nnode_modules/\n"
	gitignorePath := filepath.Join(tmpDir, ".gitignore")
	os.WriteFile(gitignorePath, []byte(existingGitignore), 0644)

	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validator.NewManager())

	err := secretsMgr.Init(initialize.Options{})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Read .gitignore and count occurrences
	content, err := os.ReadFile(gitignorePath)
	if err != nil {
		t.Fatalf("Failed to read .gitignore: %v", err)
	}

	gitignoreContent := string(content)

	// Count occurrences of .secrets_yohnah
	count := 0
	lines := strings.Split(gitignoreContent, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == ".secrets_yohnah" {
			count++
		}
	}

	if count != 1 {
		t.Errorf("Expected .secrets_yohnah to appear exactly once, but found %d occurrences", count)
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestInitWithInvalidConfigFile tests that init fails with invalid config.yml
func TestInitWithInvalidConfigFile(t *testing.T) {
	tmpDir := setupTestDir(t)
	setupTestPassword(t)
	initGitRepo(t, tmpDir)

	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	// Create .secrets_yohnah directory
	secretsDir := filepath.Join(tmpDir, ".secrets_yohnah")
	if err := os.MkdirAll(secretsDir, 0755); err != nil {
		t.Fatalf("Failed to create secrets directory: %v", err)
	}

	// Create invalid config.yml with unknown field
	invalidConfig := `database: /tmp/test.kdbx
keyfile: /tmp/test.keyfile
unknown_field: "this is invalid"
`
	configPath := filepath.Join(secretsDir, "config.yml")
	if err := os.WriteFile(configPath, []byte(invalidConfig), 0644); err != nil {
		t.Fatalf("Failed to create invalid config file: %v", err)
	}

	flags := &types.GlobalFlags{
		Force: true,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(flags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepass.NewManager(), output.NewManager(), validator.NewManager())

	// Init should fail due to invalid config
	err := secretsMgr.Init(initialize.Options{})
	if err == nil {
		t.Fatal("Expected init to fail with invalid config, but it succeeded")
	}

	// Verify error message mentions validation
	if !containsString(err.Error(), "validation") && !containsString(err.Error(), "unknown field") {
		t.Errorf("Expected error to mention validation or unknown field, got: %v", err)
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsStringHelper(s, substr)))
}

func containsStringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
