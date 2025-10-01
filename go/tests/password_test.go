package test

import (
	"os"
	"testing"

	"github.com/Yohnah/secrets/internal/cli"
)

func TestPasswordFromEnvironment(t *testing.T) {
	// Clean up environment after test
	defer func() {
		os.Unsetenv("SECRETS_YOHNAH_PASSWORD")
	}()
	
	// Set password in environment
	os.Setenv("SECRETS_YOHNAH_PASSWORD", "test-env-password")
	
	// Create new app after setting env var
	app := cli.NewApp()
	cliApp, ok := app.(*cli.CLIApp)
	if !ok {
		t.Fatal("Could not cast app to CLIApp")
	}
	
	// Test that password is accessible from environment
	if cliApp.GetPassword() != "test-env-password" {
		t.Errorf("Expected password from env var, got '%s'", cliApp.GetPassword())
	}
}

func TestPasswordProvider(t *testing.T) {
	logger := cli.NewLogger(false)
	passwordProvider := cli.NewPasswordProvider(logger)
	
	if passwordProvider == nil {
		t.Fatal("NewPasswordProvider() returned nil")
	}
	
	// Test that provider implements PasswordProvider interface
	_, ok := passwordProvider.(cli.PasswordProvider)
	if !ok {
		t.Fatal("NewPasswordProvider() doesn't implement PasswordProvider interface")
	}
}

func TestPasswordEnvironmentIntegration(t *testing.T) {
	// Clean up environment after test
	defer func() {
		os.Unsetenv("SECRETS_YOHNAH_PASSWORD")
	}()
	
	// Test without environment variable
	app := cli.NewApp()
	cliApp, ok := app.(*cli.CLIApp)
	if !ok {
		t.Fatal("Could not cast app to CLIApp")
	}
	
	if cliApp.GetPassword() != "" {
		t.Errorf("Expected empty password when env var not set, got '%s'", cliApp.GetPassword())
	}
	
	// Set environment variable
	os.Setenv("SECRETS_YOHNAH_PASSWORD", "env-password-123")
	
	// Create new app to pick up environment variable
	newApp := cli.NewApp()
	newCliApp, ok := newApp.(*cli.CLIApp)
	if !ok {
		t.Fatal("Could not cast new app to CLIApp")
	}
	
	if newCliApp.GetPassword() != "env-password-123" {
		t.Errorf("Expected password from env var, got '%s'", newCliApp.GetPassword())
	}
}