package test

import (
	"testing"

	"github.com/Yohnah/secrets/internal/cli"
)

func TestNewApp(t *testing.T) {
	// Test app creation
	app := cli.NewApp()
	
	if app == nil {
		t.Fatal("NewApp() returned nil")
	}
	
	// Test that app implements App interface
	_, ok := app.(cli.App)
	if !ok {
		t.Fatal("NewApp() doesn't implement App interface")
	}
}

func TestAppExecution(t *testing.T) {
	app := cli.NewApp()
	
	// Test that Execute method exists by trying to call it
	// We expect it to fail because we're not providing proper CLI context
	// but the method should exist
	err := app.Execute()
	// We don't care about the error, just that the method exists and is callable
	_ = err
}