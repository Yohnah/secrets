package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/cli"
)

// TestKeePassManager tests the KeePass management functionality
func TestKeePassManager(t *testing.T) {
	logger := cli.NewLogger(true)
	keepassManager := cli.NewKeePassManager(logger)
	
	tempDir := t.TempDir()
	
	// Test 1: Database and keyfile do not exist initially
	t.Run("InitialState", func(t *testing.T) {
		dbPath := filepath.Join(tempDir, "test.kdbx")
		keyfilePath := filepath.Join(tempDir, "test.keyfile")
		
		if keepassManager.DatabaseExists(dbPath) {
			t.Error("Database should not exist initially")
		}
		
		if keepassManager.KeyfileExists(keyfilePath) {
			t.Error("Keyfile should not exist initially")
		}
	})
	
	// Test 2: Generate keyfile
	t.Run("GenerateKeyfile", func(t *testing.T) {
		keyfilePath := filepath.Join(tempDir, "test.keyfile")
		
		err := keepassManager.GenerateKeyfile(keyfilePath)
		if err != nil {
			t.Fatalf("Failed to generate keyfile: %v", err)
		}
		
		// Verify keyfile exists
		if !keepassManager.KeyfileExists(keyfilePath) {
			t.Error("Keyfile should exist after generation")
		}
		
		// Verify keyfile has correct size (512 bytes)
		stat, err := os.Stat(keyfilePath)
		if err != nil {
			t.Fatalf("Failed to stat keyfile: %v", err)
		}
		
		if stat.Size() != 512 {
			t.Errorf("Expected keyfile size 512 bytes, got %d", stat.Size())
		}
		
		// Verify keyfile has restrictive permissions
		mode := stat.Mode()
		expectedPerm := os.FileMode(0400) // read-only for owner
		if mode.Perm() != expectedPerm {
			t.Errorf("Expected keyfile permissions %v, got %v", expectedPerm, mode.Perm())
		}
	})
	
	// Test 3: Path validation
	t.Run("PathValidation", func(t *testing.T) {
		dbPath := filepath.Join(tempDir, "subdir", "test.kdbx")
		keyfilePath := filepath.Join(tempDir, "subdir", "test.keyfile")
		
		err := keepassManager.ValidatePaths(dbPath, keyfilePath)
		if err != nil {
			t.Fatalf("Path validation should succeed: %v", err)
		}
		
		// Verify directories were created
		if _, err := os.Stat(filepath.Dir(dbPath)); os.IsNotExist(err) {
			t.Error("Database directory should have been created")
		}
		
		// Test invalid paths (same path for db and keyfile)
		err = keepassManager.ValidatePaths(dbPath, dbPath)
		if err == nil {
			t.Error("Validation should fail when database and keyfile paths are the same")
		}
	})
	
	// Test 4: Create database (simplified test since we can't easily verify the KeePass format)
	t.Run("CreateDatabase", func(t *testing.T) {
		dbPath := filepath.Join(tempDir, "create_test.kdbx")
		keyfilePath := filepath.Join(tempDir, "create_test.keyfile")
		password := "testpassword123"
		
		// Generate keyfile first
		err := keepassManager.GenerateKeyfile(keyfilePath)
		if err != nil {
			t.Fatalf("Failed to generate keyfile: %v", err)
		}
		
		// Create database
		err = keepassManager.CreateDatabase(dbPath, keyfilePath, password)
		if err != nil {
			t.Fatalf("Failed to create database: %v", err)
		}
		
		// Verify database file was created
		if !keepassManager.DatabaseExists(dbPath) {
			t.Error("Database should exist after creation")
		}
		
		// Verify database file has some content
		stat, err := os.Stat(dbPath)
		if err != nil {
			t.Fatalf("Failed to stat database: %v", err)
		}
		
		if stat.Size() == 0 {
			t.Error("Database file should not be empty")
		}
	})
}

// TestInteractivePrompter tests the interactive prompting functionality
func TestInteractivePrompter(t *testing.T) {
	logger := cli.NewLogger(false) // Use false to avoid debug output in tests
	prompter := cli.NewInteractivePrompter(logger)
	
	// Test 1: YesNo with force mode
	t.Run("YesNoForceMode", func(t *testing.T) {
		// Test force mode with default "yes"
		result, err := prompter.AskYesNo("Test question", "yes", true)
		if err != nil {
			t.Fatalf("AskYesNo failed: %v", err)
		}
		
		if !result {
			t.Error("Expected true when default is 'yes' in force mode")
		}
		
		// Test force mode with default "no"
		result, err = prompter.AskYesNo("Test question", "no", true)
		if err != nil {
			t.Fatalf("AskYesNo failed: %v", err)
		}
		
		if result {
			t.Error("Expected false when default is 'no' in force mode")
		}
	})
	
	// Test 2: String with force mode
	t.Run("StringForceMode", func(t *testing.T) {
		defaultValue := "default_value"
		result, err := prompter.AskString("Test question", defaultValue, true)
		if err != nil {
			t.Fatalf("AskString failed: %v", err)
		}
		
		if result != defaultValue {
			t.Errorf("Expected '%s', got '%s'", defaultValue, result)
		}
	})
	
	// Note: Interactive tests (without force mode) are difficult to test automatically
	// since they require user input. In a real-world scenario, you might use mocks
	// or dependency injection to simulate user input for testing.
}

// TestKeePassInitIntegration tests the integration of KeePass creation in init command
func TestKeePassInitIntegration(t *testing.T) {
	// This test verifies that all the components work together
	// by checking the interfaces and basic functionality
	
	logger := cli.NewLogger(false)
	
	// Create all components
	gitFinder := cli.NewGitRootFinder(logger)
	configManager := cli.NewConfigManager(logger)
	gitIgnoreManager := cli.NewGitIgnoreManager(logger)
	passwordProvider := cli.NewPasswordProvider(logger)
	keepassManager := cli.NewKeePassManager(logger)
	prompter := cli.NewInteractivePrompter(logger)
	
	// Verify all interfaces are properly implemented
	if gitFinder == nil {
		t.Error("GitFinder should not be nil")
	}
	if configManager == nil {
		t.Error("ConfigManager should not be nil")
	}
	if gitIgnoreManager == nil {
		t.Error("GitIgnoreManager should not be nil")
	}
	if passwordProvider == nil {
		t.Error("PasswordProvider should not be nil")
	}
	if keepassManager == nil {
		t.Error("KeePassManager should not be nil")
	}
	if prompter == nil {
		t.Error("InteractivePrompter should not be nil")
	}
	
	// Test default config values
	defaultConfig := configManager.GetDefaultConfig()
	if defaultConfig.DatabasePath != "./secrets.kdbx" {
		t.Errorf("Expected default database path './secrets.kdbx', got '%s'", defaultConfig.DatabasePath)
	}
	if defaultConfig.KeyfilePath != "./secrets.keyfile" {
		t.Errorf("Expected default keyfile path './secrets.keyfile', got '%s'", defaultConfig.KeyfilePath)
	}
}