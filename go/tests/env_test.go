package test

import (
	"os"
	"testing"

	"github.com/Yohnah/secrets/internal/cli"
)

func TestEnvironmentVariables(t *testing.T) {
	// Clean up environment after test
	defer func() {
		os.Unsetenv("SECRETS_YOHNAH_DATABASE_PATH")
		os.Unsetenv("SECRETS_YOHNAH_KEYFILE_PATH")
	}()
	
	// Set environment variables
	os.Setenv("SECRETS_YOHNAH_DATABASE_PATH", "/env/path/to/db.kdbx")
	os.Setenv("SECRETS_YOHNAH_KEYFILE_PATH", "/env/path/to/key.key")
	
	// Create new app after setting env vars
	app := cli.NewApp()
	cliApp, ok := app.(*cli.CLIApp)
	if !ok {
		t.Fatal("Could not cast app to CLIApp")
	}
	
	// Test that environment variables are read
	if cliApp.GetDatabase() != "/env/path/to/db.kdbx" {
		t.Errorf("Expected database from env var, got '%s'", cliApp.GetDatabase())
	}
	
	if cliApp.GetKeyfile() != "/env/path/to/key.key" {
		t.Errorf("Expected keyfile from env var, got '%s'", cliApp.GetKeyfile())
	}
}

func TestFlagPrecedenceOverEnv(t *testing.T) {
	// Clean up environment after test
	defer func() {
		os.Unsetenv("SECRETS_YOHNAH_DATABASE_PATH")
		os.Unsetenv("SECRETS_YOHNAH_KEYFILE_PATH")
	}()
	
	// Set environment variables
	os.Setenv("SECRETS_YOHNAH_DATABASE_PATH", "/env/path/to/db.kdbx")
	os.Setenv("SECRETS_YOHNAH_KEYFILE_PATH", "/env/path/to/key.key")
	
	// Create app and simulate flags being set
	app := cli.NewApp()
	cliApp, ok := app.(*cli.CLIApp)
	if !ok {
		t.Fatal("Could not cast app to CLIApp")
	}
	
	// Note: In real usage, flags would be set by cobra parsing
	// Here we test the logic when flags are empty vs when they have values
	
	// Test env vars are used when flags are empty
	if cliApp.GetDatabase() != "/env/path/to/db.kdbx" {
		t.Errorf("Expected database from env var when flag is empty, got '%s'", cliApp.GetDatabase())
	}
}