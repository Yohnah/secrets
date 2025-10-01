package cli

import (
	"testing"
)

func TestNewCLIApp(t *testing.T) {
	// Test data
	version := "v1.0.0"
	buildTime := "2025-01-01T00:00:00Z"
	gitCommit := "abc123"
	
	// Create app
	app := NewCLIApp(version, buildTime, gitCommit)
	
	// Verify app was created
	if app == nil {
		t.Fatal("NewCLIApp returned nil")
	}
	
	// Verify fields
	if app.version != version {
		t.Errorf("Expected version %s, got %s", version, app.version)
	}
	
	if app.buildTime != buildTime {
		t.Errorf("Expected buildTime %s, got %s", buildTime, app.buildTime)
	}
	
	if app.gitCommit != gitCommit {
		t.Errorf("Expected gitCommit %s, got %s", gitCommit, app.gitCommit)
	}
	
	// Verify root command was set up
	if app.rootCmd == nil {
		t.Error("Root command was not initialized")
	}
	
	if app.rootCmd.Use != "secrets" {
		t.Errorf("Expected command use 'secrets', got '%s'", app.rootCmd.Use)
	}
}

func TestCLIAppBasicFunctionality(t *testing.T) {
	app := NewCLIApp("test", "test-time", "test-commit")
	
	// Test that app is properly initialized
	if app.rootCmd == nil {
		t.Error("Root command was not initialized")
	}
	
	// Test that we can get the version
	if app.rootCmd.Version != "test" {
		t.Errorf("Expected version 'test', got '%s'", app.rootCmd.Version)
	}
}
