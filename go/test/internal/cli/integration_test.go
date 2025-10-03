package cli_test

import (
	"testing"

	"github.com/Yohnah/secrets/internal/cli"
	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/prompt"
)

// TestComponentsIntegration verifies that all major components work together
func TestComponentsIntegration(t *testing.T) {
	// Test that all components can be instantiated without errors
	configMgr := config.NewConfigManager()
	if configMgr == nil {
		t.Error("Expected ConfigManager to be created, got nil")
	}

	dbMgr := keepass.NewDatabaseManager()
	if dbMgr == nil {
		t.Error("Expected DatabaseManager to be created, got nil")
	}

	prompter := prompt.NewInteractivePrompter(true)
	if prompter == nil {
		t.Error("Expected InteractivePrompter to be created, got nil")
	}
}

// TestConfigManagerWithKeePassIntegration tests the integration between config and keepass
func TestConfigManagerWithKeePassIntegration(t *testing.T) {
	configMgr := config.NewConfigManager()
	dbMgr := keepass.NewDatabaseManager()

	// Test configuration resolution
	cfg, err := configMgr.Load(config.ConfigOptions{
		DatabaseFlag: "/test/flag.kdbx",
		KeyfileFlag:  "/test/flag.keyfile",
		BasePath:     "/test/base",
	})

	if err != nil {
		t.Fatalf("Expected no error from ConfigManager.Load, got %v", err)
	}

	if cfg.DatabasePath != "/test/flag.kdbx" {
		t.Errorf("Expected database path /test/flag.kdbx, got %s", cfg.DatabasePath)
	}

	if cfg.KeyfilePath != "/test/flag.keyfile" {
		t.Errorf("Expected keyfile path /test/flag.keyfile, got %s", cfg.KeyfilePath)
	}

	// Test that DatabaseManager can check existence (even if files don't exist)
	exists := dbMgr.Exists(cfg.DatabasePath)
	if exists {
		t.Error("Expected false for non-existent database, got true")
	}
}

// TestInitCommandExists verifies that the init command can be created
func TestInitCommandExists(t *testing.T) {
	cmd := cli.NewInitCommand()
	if cmd == nil {
		t.Error("Expected init command to be created, got nil")
	}

	if cmd.Use != "init [secrets-file]" {
		t.Errorf("Expected command use to be 'init [secrets-file]', got %s", cmd.Use)
	}

	// Verify command-specific flags exist
	hasNoDatabaseFlag := cmd.Flags().Lookup("no-create-database") != nil
	if !hasNoDatabaseFlag {
		t.Error("Expected init command to have --no-create-database flag")
	}

	// Note: --force is a global/persistent flag defined in main.go, not a command-specific flag
}

// TestConfigPrecedenceIntegration tests that precedence works as expected
func TestConfigPrecedenceIntegration(t *testing.T) {
	configMgr := config.NewConfigManager()

	// Test 1: Flags override everything
	cfg, err := configMgr.Load(config.ConfigOptions{
		DatabaseFlag: "/flag/wins.kdbx",
		KeyfileFlag:  "/flag/wins.keyfile",
		BasePath:     "/base",
	})

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if cfg.DatabasePath != "/flag/wins.kdbx" {
		t.Errorf("Expected flags to have highest precedence, got %s", cfg.DatabasePath)
	}

	// Test 2: Defaults when nothing is set
	cfg2, err := configMgr.Load(config.ConfigOptions{
		BasePath: "/base",
	})

	if err != nil {
		t.Fatalf("Expected no error for defaults, got %v", err)
	}

	expectedDB := "/base/secrets.kdbx"
	if cfg2.DatabasePath != expectedDB {
		t.Errorf("Expected default database path %s, got %s", expectedDB, cfg2.DatabasePath)
	}
}
