package config_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/config"
)

func TestConfigManager_Load_Defaults(t *testing.T) {
	configMgr := config.NewConfigManager()

	cfg, err := configMgr.Load(config.ConfigOptions{
		BasePath: "/test/base",
	})

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	expectedDB := "/test/base/secrets.kdbx"
	expectedKey := "/test/base/secrets.keyfile"

	if cfg.DatabasePath != expectedDB {
		t.Errorf("Expected database path %s, got %s", expectedDB, cfg.DatabasePath)
	}

	if cfg.KeyfilePath != expectedKey {
		t.Errorf("Expected keyfile path %s, got %s", expectedKey, cfg.KeyfilePath)
	}
}

func TestConfigManager_Load_EnvironmentVariables(t *testing.T) {
	// Setup environment variables
	originalDB := os.Getenv("SECRETS_YOHNAH_DATABASE_PATH")
	originalKey := os.Getenv("SECRETS_YOHNAH_KEYFILE_PATH")
	defer func() {
		os.Setenv("SECRETS_YOHNAH_DATABASE_PATH", originalDB)
		os.Setenv("SECRETS_YOHNAH_KEYFILE_PATH", originalKey)
	}()

	os.Setenv("SECRETS_YOHNAH_DATABASE_PATH", "/env/test.kdbx")
	os.Setenv("SECRETS_YOHNAH_KEYFILE_PATH", "/env/test.keyfile")

	configMgr := config.NewConfigManager()

	cfg, err := configMgr.Load(config.ConfigOptions{
		BasePath: "/test/base",
	})

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if cfg.DatabasePath != "/env/test.kdbx" {
		t.Errorf("Expected database path /env/test.kdbx, got %s", cfg.DatabasePath)
	}

	if cfg.KeyfilePath != "/env/test.keyfile" {
		t.Errorf("Expected keyfile path /env/test.keyfile, got %s", cfg.KeyfilePath)
	}
}

func TestConfigManager_Load_ConfigFile(t *testing.T) {
	// Create temporary config file
	tempDir, err := ioutil.TempDir("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "test_config.yml")
	configContent := `database_path: config/custom.kdbx
keyfile_path: config/custom.keyfile`

	err = ioutil.WriteFile(configPath, []byte(configContent), 0600)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Setup environment variables (should be overridden by config file)
	originalDB := os.Getenv("SECRETS_YOHNAH_DATABASE_PATH")
	originalKey := os.Getenv("SECRETS_YOHNAH_KEYFILE_PATH")
	defer func() {
		os.Setenv("SECRETS_YOHNAH_DATABASE_PATH", originalDB)
		os.Setenv("SECRETS_YOHNAH_KEYFILE_PATH", originalKey)
	}()

	os.Setenv("SECRETS_YOHNAH_DATABASE_PATH", "/env/should_be_overridden.kdbx")
	os.Setenv("SECRETS_YOHNAH_KEYFILE_PATH", "/env/should_be_overridden.keyfile")

	configMgr := config.NewConfigManager()

	cfg, err := configMgr.Load(config.ConfigOptions{
		ConfigPath: configPath,
		BasePath:   "/test/base",
	})

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	expectedDB := "/test/base/config/custom.kdbx"
	expectedKey := "/test/base/config/custom.keyfile"

	if cfg.DatabasePath != expectedDB {
		t.Errorf("Expected database path %s, got %s", expectedDB, cfg.DatabasePath)
	}

	if cfg.KeyfilePath != expectedKey {
		t.Errorf("Expected keyfile path %s, got %s", expectedKey, cfg.KeyfilePath)
	}
}

func TestConfigManager_Load_Flags_HighestPrecedence(t *testing.T) {
	// Create temporary config file
	tempDir, err := ioutil.TempDir("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "test_config.yml")
	configContent := `database_path: /config/should_be_overridden.kdbx
keyfile_path: /config/should_be_overridden.keyfile`

	err = ioutil.WriteFile(configPath, []byte(configContent), 0600)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Setup environment variables (should be overridden by flags)
	originalDB := os.Getenv("SECRETS_YOHNAH_DATABASE_PATH")
	originalKey := os.Getenv("SECRETS_YOHNAH_KEYFILE_PATH")
	defer func() {
		os.Setenv("SECRETS_YOHNAH_DATABASE_PATH", originalDB)
		os.Setenv("SECRETS_YOHNAH_KEYFILE_PATH", originalKey)
	}()

	os.Setenv("SECRETS_YOHNAH_DATABASE_PATH", "/env/should_be_overridden.kdbx")
	os.Setenv("SECRETS_YOHNAH_KEYFILE_PATH", "/env/should_be_overridden.keyfile")

	configMgr := config.NewConfigManager()

	cfg, err := configMgr.Load(config.ConfigOptions{
		DatabaseFlag: "/flag/wins.kdbx",
		KeyfileFlag:  "/flag/wins.keyfile",
		ConfigPath:   configPath,
		BasePath:     "/test/base",
	})

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if cfg.DatabasePath != "/flag/wins.kdbx" {
		t.Errorf("Expected database path /flag/wins.kdbx, got %s", cfg.DatabasePath)
	}

	if cfg.KeyfilePath != "/flag/wins.keyfile" {
		t.Errorf("Expected keyfile path /flag/wins.keyfile, got %s", cfg.KeyfilePath)
	}
}

func TestConfigManager_ResolvePath(t *testing.T) {
	configMgr := config.NewConfigManager()

	// Test absolute path
	result := configMgr.ResolvePath("/base/path", "/absolute/path/file.kdbx")
	expected := "/absolute/path/file.kdbx"
	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}

	// Test relative path
	result = configMgr.ResolvePath("/base/path", "relative/file.kdbx")
	expected = "/base/path/relative/file.kdbx"
	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}

	// Test filename only
	result = configMgr.ResolvePath("/base/path", "file.kdbx")
	expected = "/base/path/file.kdbx"
	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestConfigManager_Save(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "test_save.yml")
	config := &config.Config{
		DatabasePath: "test.kdbx",
		KeyfilePath:  "test.keyfile",
	}

	configMgr := config.NewConfigManager()
	err = configMgr.Save(configPath, config)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify file was created and has correct content
	content, err := ioutil.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read saved file: %v", err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "database_path: test.kdbx") {
		t.Errorf("Expected file to contain 'database_path: test.kdbx', got: %s", contentStr)
	}

	if !strings.Contains(contentStr, "keyfile_path: test.keyfile") {
		t.Errorf("Expected file to contain 'keyfile_path: test.keyfile', got: %s", contentStr)
	}

	// Verify file permissions
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}

	expectedPerm := os.FileMode(0600)
	if info.Mode().Perm() != expectedPerm {
		t.Errorf("Expected file permissions %v, got %v", expectedPerm, info.Mode().Perm())
	}
}
