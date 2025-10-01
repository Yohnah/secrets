package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/logger"
)

func TestDefaultManager(t *testing.T) {
	log := logger.New(false)
	manager := NewManager(log)
	
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	configPath := filepath.Join(tmpDir, "config.yml")
	
	t.Run("CreateDefaultConfig", func(t *testing.T) {
		err := manager.CreateDefaultConfig(configPath)
		if err != nil {
			t.Fatalf("CreateDefaultConfig failed: %v", err)
		}
		
		// Verify file exists
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			t.Error("Config file was not created")
		}
	})
	
	t.Run("LoadConfig", func(t *testing.T) {
		config, err := manager.LoadConfig(configPath)
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		
		// Verify default values
		if config.DatabasePath != "secrets.kdbx" {
			t.Errorf("Expected DatabasePath 'secrets.kdbx', got '%s'", config.DatabasePath)
		}
		
		if config.KeyfilePath != "secrets.keyfile" {
			t.Errorf("Expected KeyfilePath 'secrets.keyfile', got '%s'", config.KeyfilePath)
		}
	})
	
	t.Run("SaveConfig", func(t *testing.T) {
		config := &Config{
			DatabasePath: "test.kdbx",
			KeyfilePath:  "test.keyfile",
		}
		
		testPath := filepath.Join(tmpDir, "test_config.yml")
		err := manager.SaveConfig(config, testPath)
		if err != nil {
			t.Fatalf("SaveConfig failed: %v", err)
		}
		
		// Load and verify
		loadedConfig, err := manager.LoadConfig(testPath)
		if err != nil {
			t.Fatalf("Failed to load saved config: %v", err)
		}
		
		if loadedConfig.DatabasePath != config.DatabasePath {
			t.Errorf("Expected DatabasePath '%s', got '%s'", config.DatabasePath, loadedConfig.DatabasePath)
		}
		
		if loadedConfig.KeyfilePath != config.KeyfilePath {
			t.Errorf("Expected KeyfilePath '%s', got '%s'", config.KeyfilePath, loadedConfig.KeyfilePath)
		}
	})
	
	t.Run("LoadConfigNonExistent", func(t *testing.T) {
		nonExistentPath := filepath.Join(tmpDir, "nonexistent.yml")
		_, err := manager.LoadConfig(nonExistentPath)
		if err == nil {
			t.Error("Expected error for non-existent config file")
		}
	})
}