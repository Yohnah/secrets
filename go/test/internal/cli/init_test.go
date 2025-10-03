package cli_test

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/cli"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func setupTestEnvironment(t *testing.T) (string, func()) {
	// Create temporary directory
	tempDir, err := ioutil.TempDir("", "init_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Save original working directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	// Change to temp directory
	err = os.Chdir(tempDir)
	if err != nil {
		t.Fatalf("Failed to change to temp dir: %v", err)
	}

	// Save original environment variables
	originalPassword := os.Getenv("SECRETS_YOHNAH_PASSWORD")
	originalDB := os.Getenv("SECRETS_YOHNAH_DATABASE_PATH")
	originalKey := os.Getenv("SECRETS_YOHNAH_KEYFILE_PATH")

	// Cleanup function
	cleanup := func() {
		os.Chdir(originalDir)
		os.RemoveAll(tempDir)
		os.Setenv("SECRETS_YOHNAH_PASSWORD", originalPassword)
		os.Setenv("SECRETS_YOHNAH_DATABASE_PATH", originalDB)
		os.Setenv("SECRETS_YOHNAH_KEYFILE_PATH", originalKey)
		viper.Reset()
	}

	return tempDir, cleanup
}

func TestInitCommand_Success_WithForce(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Set password environment variable
	os.Setenv("SECRETS_YOHNAH_PASSWORD", "test_password_123")

	// Create init command
	cmd := cli.NewInitCommand()

	// Set flags
	cmd.Flags().Set("force", "true")
	cmd.Flags().Set("verbose", "true")
	cmd.Flags().Set("ignore-git-repository", "true")

	// Execute command
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify directory was created
	secretsDir := ".secrets_yohnah"
	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		t.Error("Expected .secrets_yohnah directory to be created")
	}

	// Verify config file was created
	configPath := filepath.Join(secretsDir, "config.yml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Expected config.yml to be created")
	}

	// Verify database was created
	dbPath := filepath.Join(secretsDir, "secrets.kdbx")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Expected secrets.kdbx to be created")
	}

	// Verify keyfile was created
	keyfilePath := filepath.Join(secretsDir, "secrets.keyfile")
	if _, err := os.Stat(keyfilePath); os.IsNotExist(err) {
		t.Error("Expected secrets.keyfile to be created")
	}

	// Verify keyfile permissions
	info, err := os.Stat(keyfilePath)
	if err != nil {
		t.Fatalf("Failed to stat keyfile: %v", err)
	}

	expectedPerm := os.FileMode(0600)
	if info.Mode().Perm() != expectedPerm {
		t.Errorf("Expected keyfile permissions %v, got %v", expectedPerm, info.Mode().Perm())
	}
}

func TestInitCommand_NoCreateDatabase_Flag(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create init command
	cmd := cli.NewInitCommand()

	// Set flags
	cmd.Flags().Set("force", "true")
	cmd.Flags().Set("no-create-database", "true")
	cmd.Flags().Set("ignore-git-repository", "true")

	// Execute command
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify directory was created
	secretsDir := ".secrets_yohnah"
	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		t.Error("Expected .secrets_yohnah directory to be created")
	}

	// Verify config file was created
	configPath := filepath.Join(secretsDir, "config.yml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Expected config.yml to be created")
	}

	// Verify database was NOT created
	dbPath := filepath.Join(secretsDir, "secrets.kdbx")
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Error("Expected secrets.kdbx NOT to be created with --no-create-database flag")
	}

	// Verify keyfile was NOT created
	keyfilePath := filepath.Join(secretsDir, "secrets.keyfile")
	if _, err := os.Stat(keyfilePath); !os.IsNotExist(err) {
		t.Error("Expected secrets.keyfile NOT to be created with --no-create-database flag")
	}
}

func TestInitCommand_AlreadyInitialized(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Set password environment variable
	os.Setenv("SECRETS_YOHNAH_PASSWORD", "test_password_123")

	// Create .secrets_yohnah directory and config file manually
	secretsDir := ".secrets_yohnah"
	err := os.MkdirAll(secretsDir, 0700)
	if err != nil {
		t.Fatalf("Failed to create secrets dir: %v", err)
	}

	configPath := filepath.Join(secretsDir, "config.yml")
	configContent := `database_path: secrets.kdbx
keyfile_path: secrets.keyfile`
	err = ioutil.WriteFile(configPath, []byte(configContent), 0600)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	// Create init command
	cmd := cli.NewInitCommand()

	// Set flags
	cmd.Flags().Set("force", "true")
	cmd.Flags().Set("ignore-git-repository", "true")
	var buf bytes.Buffer
	cmd.SetOutput(&buf)

	// Execute command
	err = cmd.Execute()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify message indicates already initialized
	output := buf.String()
	if !strings.Contains(output, "already been initialized") {
		t.Errorf("Expected 'already initialized' message, got: %s", output)
	}
}

func TestInitCommand_CustomPaths_WithFlags(t *testing.T) {
	tempDir, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Set password environment variable
	os.Setenv("SECRETS_YOHNAH_PASSWORD", "test_password_123")

	// Create custom directories
	customDir := filepath.Join(tempDir, "custom")
	err := os.MkdirAll(customDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create custom dir: %v", err)
	}

	customDBPath := filepath.Join(customDir, "custom.kdbx")
	customKeyfilePath := filepath.Join(customDir, "custom.keyfile")

	// Setup viper for global flags
	viper.Set("database", customDBPath)
	viper.Set("keyfile", customKeyfilePath)

	// Create root command to simulate parent flags
	rootCmd := &cobra.Command{Use: "secrets"}
	rootCmd.PersistentFlags().String("database", "", "database path")
	rootCmd.PersistentFlags().String("keyfile", "", "keyfile path")

	// Mark flags as changed (simulate explicit setting)
	rootCmd.PersistentFlags().Set("database", customDBPath)
	rootCmd.PersistentFlags().Set("keyfile", customKeyfilePath)

	// Create init command and add to root
	initCmd := cli.NewInitCommand()
	rootCmd.AddCommand(initCmd)

	// Set command line arguments
	rootCmd.SetArgs([]string{"--database", customDBPath, "--keyfile", customKeyfilePath, "init", "--force", "--verbose", "--ignore-git-repository"})

	// Execute command through root
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify directory was created
	secretsDir := ".secrets_yohnah"
	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		t.Error("Expected .secrets_yohnah directory to be created")
	}

	// Verify database was created in custom location
	if _, err := os.Stat(customDBPath); os.IsNotExist(err) {
		t.Error("Expected custom database to be created")
	}

	// Verify keyfile was created in custom location
	if _, err := os.Stat(customKeyfilePath); os.IsNotExist(err) {
		t.Error("Expected custom keyfile to be created")
	}
}

func TestInitCommand_ConfigFilePrecedence(t *testing.T) {
	tempDir, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Set password environment variable
	os.Setenv("SECRETS_YOHNAH_PASSWORD", "test_password_123")

	// Set environment variables (should be overridden by config file)
	os.Setenv("SECRETS_YOHNAH_DATABASE_PATH", filepath.Join(tempDir, "env_should_be_ignored.kdbx"))
	os.Setenv("SECRETS_YOHNAH_KEYFILE_PATH", filepath.Join(tempDir, "env_should_be_ignored.keyfile"))

	// Create custom config file
	configDir := filepath.Join(tempDir, "config")
	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}

	customConfigPath := filepath.Join(tempDir, "custom_config.yml")
	configContent := `database_path: config/from_config.kdbx
keyfile_path: config/from_config.keyfile`
	err = ioutil.WriteFile(customConfigPath, []byte(configContent), 0600)
	if err != nil {
		t.Fatalf("Failed to create custom config: %v", err)
	}

	// Setup viper for global flags
	viper.Set("config", customConfigPath)

	// Create root command to simulate parent flags
	rootCmd := &cobra.Command{Use: "secrets"}
	rootCmd.PersistentFlags().String("config", "", "config path")

	// Create init command and add to root
	initCmd := cli.NewInitCommand()
	rootCmd.AddCommand(initCmd)

	// Set command line arguments
	rootCmd.SetArgs([]string{"--config", customConfigPath, "init", "--force", "--verbose", "--ignore-git-repository"})

	// Execute command through root
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify database was created using config file path (not environment variable)
	expectedDBPath := filepath.Join(".secrets_yohnah", "config", "from_config.kdbx")
	if _, err := os.Stat(expectedDBPath); os.IsNotExist(err) {
		t.Errorf("Expected database at %s (from config file), but not found", expectedDBPath)
	}

	// Verify keyfile was created using config file path
	expectedKeyfilePath := filepath.Join(".secrets_yohnah", "config", "from_config.keyfile")
	if _, err := os.Stat(expectedKeyfilePath); os.IsNotExist(err) {
		t.Errorf("Expected keyfile at %s (from config file), but not found", expectedKeyfilePath)
	}

	// Verify environment variable paths were NOT used
	envDBPath := filepath.Join(tempDir, "env_should_be_ignored.kdbx")
	if _, err := os.Stat(envDBPath); !os.IsNotExist(err) {
		t.Error("Environment variable database path should have been ignored")
	}
}
