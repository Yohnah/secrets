package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/logger"
)

func TestDefaultConfigManager(t *testing.T) {
	// Create a mock logger for testing
	log := logger.New(false)
	configManager := config.NewManager(log)
	
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "secrets_config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	configPath := filepath.Join(tmpDir, "config.yml")
	
	t.Run("CreateDefaultConfig", func(t *testing.T) {
		err := configManager.CreateDefaultConfig(configPath)
		if err != nil {
			t.Fatalf("CreateDefaultConfig failed: %v", err)
		}
		
		// Verify file exists
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			t.Error("Config file was not created")
		}
	})
	
	t.Run("LoadConfig", func(t *testing.T) {
		cfg, err := configManager.LoadConfig(configPath)
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		
		// Verify default values
		if cfg.DatabasePath != "secrets.kdbx" {
			t.Errorf("Expected DatabasePath 'secrets.kdbx', got '%s'", cfg.DatabasePath)
		}
		
		if cfg.KeyfilePath != "secrets.keyfile" {
			t.Errorf("Expected KeyfilePath 'secrets.keyfile', got '%s'", cfg.KeyfilePath)
		}
	})
	
	t.Run("SaveConfig", func(t *testing.T) {
		cfg := &config.Config{
			DatabasePath: "test.kdbx",
			KeyfilePath:  "test.keyfile",
		}
		
		testPath := filepath.Join(tmpDir, "test_config.yml")
		err := configManager.SaveConfig(cfg, testPath)
		if err != nil {
			t.Fatalf("SaveConfig failed: %v", err)
		}
		
		// Load and verify
		loadedConfig, err := configManager.LoadConfig(testPath)
		if err != nil {
			t.Fatalf("Failed to load saved config: %v", err)
		}
		
		if loadedConfig.DatabasePath != cfg.DatabasePath {
			t.Errorf("Expected DatabasePath '%s', got '%s'", cfg.DatabasePath, loadedConfig.DatabasePath)
		}
		
		if loadedConfig.KeyfilePath != cfg.KeyfilePath {
			t.Errorf("Expected KeyfilePath '%s', got '%s'", cfg.KeyfilePath, loadedConfig.KeyfilePath)
		}
	})
	
	t.Run("LoadConfigNonExistent", func(t *testing.T) {
		nonExistentPath := filepath.Join(tmpDir, "nonexistent.yml")
		_, err := configManager.LoadConfig(nonExistentPath)
		if err == nil {
			t.Error("Expected error for non-existent config file")
		}
	})
}