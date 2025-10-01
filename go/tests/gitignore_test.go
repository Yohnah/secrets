package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/cli"
)

// TestGitIgnoreManager tests the .gitignore management functionality
func TestGitIgnoreManager(t *testing.T) {
	logger := cli.NewLogger(true)
	gitIgnoreManager := cli.NewGitIgnoreManager(logger)
	
	// Test 1: Creating .gitignore when it doesn't exist
	t.Run("CreateGitIgnoreWhenNotExists", func(t *testing.T) {
		tempDir := t.TempDir()
		
		err := gitIgnoreManager.EnsureSecretsIgnored(tempDir)
		if err != nil {
			t.Fatalf("Failed to ensure secrets ignored: %v", err)
		}
		
		// Verify .gitignore was created
		gitignorePath := filepath.Join(tempDir, ".gitignore")
		content, err := os.ReadFile(gitignorePath)
		if err != nil {
			t.Fatalf("Failed to read created .gitignore: %v", err)
		}
		
		contentStr := string(content)
		if !strings.Contains(contentStr, ".secrets_yohnah") {
			t.Error(".gitignore should contain .secrets_yohnah entry")
		}
	})
	
	// Test 2: Adding to existing .gitignore that doesn't have the entry
	t.Run("AddToExistingGitIgnore", func(t *testing.T) {
		tempDir := t.TempDir()
		gitignorePath := filepath.Join(tempDir, ".gitignore")
		
		// Create existing .gitignore without .secrets_yohnah
		existingContent := `# Existing content
*.log
node_modules/
`
		err := os.WriteFile(gitignorePath, []byte(existingContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create test .gitignore: %v", err)
		}
		
		err = gitIgnoreManager.EnsureSecretsIgnored(tempDir)
		if err != nil {
			t.Fatalf("Failed to ensure secrets ignored: %v", err)
		}
		
		// Verify .secrets_yohnah was added
		content, err := os.ReadFile(gitignorePath)
		if err != nil {
			t.Fatalf("Failed to read updated .gitignore: %v", err)
		}
		
		contentStr := string(content)
		if !strings.Contains(contentStr, existingContent) {
			t.Error("Original content should be preserved")
		}
		if !strings.Contains(contentStr, ".secrets_yohnah") {
			t.Error(".gitignore should contain .secrets_yohnah entry")
		}
		if !strings.Contains(contentStr, "added by secrets CLI") {
			t.Error(".gitignore should contain comment about CLI addition")
		}
	})
	
	// Test 3: No change when .secrets_yohnah already exists
	t.Run("NoChangeWhenAlreadyExists", func(t *testing.T) {
		tempDir := t.TempDir()
		gitignorePath := filepath.Join(tempDir, ".gitignore")
		
		// Create .gitignore with .secrets_yohnah already present
		existingContent := `# Existing content
*.log
.secrets_yohnah
node_modules/
`
		err := os.WriteFile(gitignorePath, []byte(existingContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create test .gitignore: %v", err)
		}
		
		err = gitIgnoreManager.EnsureSecretsIgnored(tempDir)
		if err != nil {
			t.Fatalf("Failed to ensure secrets ignored: %v", err)
		}
		
		// Verify content wasn't modified
		content, err := os.ReadFile(gitignorePath)
		if err != nil {
			t.Fatalf("Failed to read .gitignore: %v", err)
		}
		
		if string(content) != existingContent {
			t.Error("Content should not be modified when .secrets_yohnah already exists")
		}
	})
	
	// Test 4: Detection of various .secrets_yohnah patterns
	t.Run("DetectVariousPatterns", func(t *testing.T) {
		patterns := []string{
			".secrets_yohnah",
			".secrets_yohnah/",
			"/.secrets_yohnah",
			"/.secrets_yohnah/",
			"**/.secrets_yohnah",
			"**/.secrets_yohnah/",
		}
		
		for _, pattern := range patterns {
			tempDir := t.TempDir()
			gitignorePath := filepath.Join(tempDir, ".gitignore")
			
			content := "# Test\n" + pattern + "\n# End\n"
			err := os.WriteFile(gitignorePath, []byte(content), 0644)
			if err != nil {
				t.Fatalf("Failed to create test .gitignore: %v", err)
			}
			
			err = gitIgnoreManager.EnsureSecretsIgnored(tempDir)
			if err != nil {
				t.Fatalf("Failed to ensure secrets ignored: %v", err)
			}
			
			// Verify content wasn't modified
			updatedContent, err := os.ReadFile(gitignorePath)
			if err != nil {
				t.Fatalf("Failed to read .gitignore: %v", err)
			}
			
			if string(updatedContent) != content {
				t.Errorf("Content should not be modified when pattern '%s' already exists", pattern)
			}
		}
	})
}

// TestInitWithGitIgnore tests the complete init process including .gitignore management
func TestInitWithGitIgnore(t *testing.T) {
	// Create a temporary directory to simulate git repository
	tempDir := t.TempDir()
	
	// Create .git directory to simulate git repository
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatalf("Failed to create .git directory: %v", err)
	}
	
	// Save original directory to restore later
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	
	// Change to temp directory
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}
	
	// Test components
	logger := cli.NewLogger(true)
	configManager := cli.NewConfigManager(logger)
	gitIgnoreManager := cli.NewGitIgnoreManager(logger)
	
	// Since we can't run actual git commands in the test environment,
	// we'll test the components individually
	
	// Test gitignore manager
	err := gitIgnoreManager.EnsureSecretsIgnored(tempDir)
	if err != nil {
		t.Fatalf("Failed to ensure secrets ignored: %v", err)
	}
	
	// Verify .gitignore was created and contains .secrets_yohnah
	gitignorePath := filepath.Join(tempDir, ".gitignore")
	content, err := os.ReadFile(gitignorePath)
	if err != nil {
		t.Fatalf("Failed to read .gitignore: %v", err)
	}
	
	if !strings.Contains(string(content), ".secrets_yohnah") {
		t.Error(".gitignore should contain .secrets_yohnah entry")
	}
	
	// Test config creation
	secretsDir := filepath.Join(tempDir, ".secrets_yohnah")
	if err := os.MkdirAll(secretsDir, 0755); err != nil {
		t.Fatalf("Failed to create secrets directory: %v", err)
	}
	
	configPath := filepath.Join(secretsDir, "config.yml")
	defaultConfig := configManager.GetDefaultConfig()
	if err := configManager.SaveConfig(configPath, defaultConfig); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}
	
	// Verify config was created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Config file should have been created")
	}
	
	// Verify config content
	loadedConfig, err := configManager.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	
	if loadedConfig.DatabasePath != "./secrets.kdbx" {
		t.Errorf("Expected default database path: ./secrets.kdbx, got: %s", loadedConfig.DatabasePath)
	}
	
	if loadedConfig.KeyfilePath != "./secrets.keyfile" {
		t.Errorf("Expected default keyfile path: ./secrets.keyfile, got: %s", loadedConfig.KeyfilePath)
	}
}

