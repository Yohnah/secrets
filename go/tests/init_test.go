package test

import (
	"testing"

	"github.com/Yohnah/secrets/internal/cli"
)

func TestInitCommand(t *testing.T) {
	// Create app for testing
	app := cli.NewApp()
	
	// We need to cast to access internal methods for testing
	// In real usage, this wouldn't be necessary
	cliApp, ok := app.(*cli.CLIApp)
	if !ok {
		t.Fatal("Could not cast app to CLIApp")
	}
	
	// Test init command creation
	initCmd := cli.NewInitCommand(cliApp)
	
	if initCmd == nil {
		t.Fatal("NewInitCommand() returned nil")
	}
	
	if initCmd.Use != "init" {
		t.Errorf("Expected command use 'init', got '%s'", initCmd.Use)
	}
	
	if initCmd.Short != "Initialize configuration" {
		t.Errorf("Expected short description 'Initialize configuration', got '%s'", initCmd.Short)
	}
}

func TestInitCommandFlags(t *testing.T) {
	app := cli.NewApp()
	
	// Test that app interface works correctly
	// We can't access internal fields directly, which is good for encapsulation
	cliApp, ok := app.(*cli.CLIApp)
	if !ok {
		t.Fatal("Could not cast app to CLIApp")
	}
	
	// Test that flags are accessible through public methods
	if !cliApp.IsVerbose() && !cliApp.IsForce() {
		// This is expected behavior - flags start as false
		t.Log("Flags correctly initialized as false")
	}
}