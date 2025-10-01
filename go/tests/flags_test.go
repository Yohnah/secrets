package test

import (
	"testing"

	"github.com/Yohnah/secrets/internal/cli"
)

func TestDatabaseFlag(t *testing.T) {
	app := cli.NewApp()
	cliApp, ok := app.(*cli.CLIApp)
	if !ok {
		t.Fatal("Could not cast app to CLIApp")
	}
	
	// Test initial state
	if cliApp.GetDatabase() != "" {
		t.Errorf("Expected empty database path, got '%s'", cliApp.GetDatabase())
	}
}

func TestKeyfileFlag(t *testing.T) {
	app := cli.NewApp()
	cliApp, ok := app.(*cli.CLIApp)
	if !ok {
		t.Fatal("Could not cast app to CLIApp")
	}
	
	// Test initial state
	if cliApp.GetKeyfile() != "" {
		t.Errorf("Expected empty keyfile path, got '%s'", cliApp.GetKeyfile())
	}
}

func TestAllFlags(t *testing.T) {
	app := cli.NewApp()
	cliApp, ok := app.(*cli.CLIApp)
	if !ok {
		t.Fatal("Could not cast app to CLIApp")
	}
	
	// Test all flags are accessible
	_ = cliApp.IsVerbose()
	_ = cliApp.IsForce()
	_ = cliApp.GetDatabase()
	_ = cliApp.GetKeyfile()
	_ = cliApp.GetPassword()
	_ = cliApp.GetConfig()
	_ = cliApp.GetSecretsConfigFile()
	
	t.Log("All flags are accessible through public methods")
}

func TestConfigFlag(t *testing.T) {
	app := cli.NewApp()
	cliApp, ok := app.(*cli.CLIApp)
	if !ok {
		t.Fatal("Could not cast app to CLIApp")
	}
	
	// Initially should be empty
	if cliApp.GetConfig() != "" {
		t.Errorf("Expected empty config path, got '%s'", cliApp.GetConfig())
	}
}

func TestSecretsConfigFileFlag(t *testing.T) {
	app := cli.NewApp()
	cliApp, ok := app.(*cli.CLIApp)
	if !ok {
		t.Fatal("Could not cast app to CLIApp")
	}
	
	// Initially should be empty
	if cliApp.GetSecretsConfigFile() != "" {
		t.Errorf("Expected empty secrets config file path, got '%s'", cliApp.GetSecretsConfigFile())
	}
}