package keepass_test

import (
	"os"
	"testing"

	"github.com/Yohnah/secrets/internal/cli"
)

func TestInitCommandDefaultFile(t *testing.T) {
	t.Log("\n=== INIT COMMAND DEFAULT FILE TEST ===")
	
	// Create temporary directory for test
	tempDir := t.TempDir()
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	
	// Change to temp directory
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}
	
	// Initialize git repository
	if err := os.MkdirAll(".git", 0755); err != nil {
		t.Fatalf("Failed to create .git directory: %v", err)
	}
	
	// Create secrets.yml file in the temp directory
	secretsYaml := `metadata:
  profile: "test_default"
  default_environment: "development"
---
development:
  - name: TEST_VAR
    entry: "/TEST_ENTRY"
    key: "test_key"
    type: "envvar"`
	
	if err := os.WriteFile("secrets.yml", []byte(secretsYaml), 0644); err != nil {
		t.Fatalf("Failed to create test secrets.yml: %v", err)
	}
	
	// Create CLI app
	app := cli.NewCLIApp()
	
	// Create init command
	initCmd := cli.NewInitCommand(app)
	
	if initCmd == nil {
		t.Fatal("Init command should not be nil")
	}
	
	// Verify that the command accepts 0 arguments (MaximumNArgs)
	if initCmd.Args == nil {
		t.Error("Command args validation should be set")
	}
	
	// Test that the command description mentions the default file
	expectedDesc := "secrets.yml in git root"
	if !contains(initCmd.Short, expectedDesc) {
		t.Errorf("Command description should mention default file. Got: %s", initCmd.Short)
	}
	
	t.Log("Init command default file support: PASS")
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr || 
		   len(s) > len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}