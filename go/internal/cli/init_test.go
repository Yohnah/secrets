package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/git"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/prompt"
)

func TestInitCommand(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "init_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	log := logger.New(false)
	configManager := config.NewManager(log)
	gitFinder := git.NewRootFinder(log)
	keepassManager := keepass.NewManager(log)
	prompter := prompt.NewInteractivePrompter(log)
	globalFlags := &GlobalFlags{Force: true}

	t.Run("NewInitCommand", func(t *testing.T) {
		cmd := NewInitCommand(log, configManager, gitFinder, keepassManager, prompter, globalFlags)
		
		if cmd == nil {
			t.Error("Expected command to be created")
		}
		
		if cmd.Use != "init" {
			t.Errorf("Expected command use to be 'init', got '%s'", cmd.Use)
		}
	})

	t.Run("InitCommand_Methods", func(t *testing.T) {
		initCmd := &InitCommand{
			logger:          log,
			configManager:   configManager,
			gitFinder:       gitFinder,
			keepassManager:  keepassManager,
			prompter:        prompter,
			globalFlags:     globalFlags,
		}

		// Test createSecretsDirectory
		secretsDir := filepath.Join(tmpDir, ".secrets_yohnah")
		err := initCmd.createSecretsDirectory(secretsDir)
		if err != nil {
			t.Errorf("createSecretsDirectory failed: %v", err)
		}

		// Verify directory was created
		if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
			t.Error("Secrets directory was not created")
		}

		// Test createOrVerifyConfig
		configPath := filepath.Join(secretsDir, "config.yml")
		err = initCmd.createOrVerifyConfig(configPath)
		if err != nil {
			t.Errorf("createOrVerifyConfig failed: %v", err)
		}

		// Verify config was created
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			t.Error("Config file was not created")
		}

		// Test isAlreadyInitialized
		if !initCmd.isAlreadyInitialized(secretsDir) {
			t.Error("Expected project to be detected as initialized")
		}
	})

	t.Run("InitCommand_PathResolution", func(t *testing.T) {
		initCmd := &InitCommand{
			logger:          log,
			configManager:   configManager,
			gitFinder:       gitFinder,
			keepassManager:  keepassManager,
			prompter:        prompter,
			globalFlags:     &GlobalFlags{
				DatabasePath: "custom.kdbx",
				KeyfilePath:  "custom.keyfile",
			},
		}

		cfg := &config.Config{
			DatabasePath: "config.kdbx",
			KeyfilePath:  "config.keyfile",
		}

		dbPath := initCmd.resolveDatabasePath(cfg, tmpDir)
		expectedDB := filepath.Join(tmpDir, "custom.kdbx")
		if dbPath != expectedDB {
			t.Errorf("Expected db path %s, got %s", expectedDB, dbPath)
		}

		keyfilePath := initCmd.resolveKeyfilePath(cfg, tmpDir)
		expectedKeyfile := filepath.Join(tmpDir, "custom.keyfile")
		if keyfilePath != expectedKeyfile {
			t.Errorf("Expected keyfile path %s, got %s", expectedKeyfile, keyfilePath)
		}
	})
}