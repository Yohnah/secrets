package logicmanager

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yohnah/secrets/internal/bdmanager"
	"github.com/Yohnah/secrets/internal/configmanager"
	"github.com/Yohnah/secrets/internal/inputmanager/cli"
	"github.com/Yohnah/secrets/internal/inputmanager/envvars"
	"github.com/Yohnah/secrets/internal/loggermanager"
	"github.com/Yohnah/secrets/internal/outputmanager"
	"github.com/Yohnah/secrets/internal/validatormanager"
)

// Logic interface defines the business logic contract
type Logic interface {
	ExecuteInit() error
}

// StandardLogic implements Logic with init workflow orchestration
type StandardLogic struct {
	config    configmanager.Config
	logger    loggermanager.Logger
	validator validatormanager.Validator
	inputCli  cli.CliReader
	inputEnv  envvars.EnvVarsReader
	output    outputmanager.Output
	bd        bdmanager.BD
}

// NewStandardLogic creates a new logic manager
func NewStandardLogic(
	config configmanager.Config,
	logger loggermanager.Logger,
	validator validatormanager.Validator,
	inputCli cli.CliReader,
	inputEnv envvars.EnvVarsReader,
	output outputmanager.Output,
	bd bdmanager.BD,
) Logic {
	return &StandardLogic{
		config:    config,
		logger:    logger,
		validator: validator,
		inputCli:  inputCli,
		inputEnv:  inputEnv,
		output:    output,
		bd:        bd,
	}
}

// ExecuteInit orchestrates the complete init workflow
func (l *StandardLogic) ExecuteInit() error {
	l.logger.Debug("Starting init workflow...")

	// Calculate paths early to check if database exists
	fullDBPath := l.calculateDatabasePath()
	fullKeyfilePath := l.calculateKeyfilePath()

	l.logger.Debug(fmt.Sprintf("Calculated database path: %s", fullDBPath))
	l.logger.Debug(fmt.Sprintf("Calculated keyfile path: %s", fullKeyfilePath))

	// Check if database already exists BEFORE interactive prompts
	if l.bd.DatabaseExists(fullDBPath) {
		if l.config.GetForceRecreate() {
			l.logger.Info(fmt.Sprintf("Removing existing database for recreation: %s", fullDBPath))
			if err := l.bd.DeleteDatabase(fullDBPath); err != nil {
				l.logger.Fatal(fmt.Sprintf("Failed to delete existing database: %s", err))
				return err
			}
		} else {
			l.logger.Info("Database already exists. Use --force-recreate to recreate it.")
			return nil
		}
	}

	if err := l.handleInteractiveConfirmations(); err != nil {
		return err
	}

	if err := l.getPassword(); err != nil {
		return err
	}

	if !l.config.GetNoCreateDatabase() {
		if err := l.createDatabase(fullDBPath, fullKeyfilePath); err != nil {
			return err
		}
	} else {
		l.logger.Info("Skipping database creation (--no-create-database)")
	}

	if err := l.createConfigFile(fullDBPath, fullKeyfilePath); err != nil {
		return err
	}

	l.logger.Info("Initialization completed successfully")
	if l.config.IsVerbose() {
		l.logger.Debug("Summary:")
		l.logger.Debug(fmt.Sprintf("  Database: %s", fullDBPath))
		if !l.config.IsIgnoreConfigFile() {
			configPath := filepath.Join(os.Getenv("HOME"), ".secrets", "config.yml")
			l.logger.Debug(fmt.Sprintf("  Config: %s", configPath))
		}
		if !l.config.GetNoKeyfile() {
			l.logger.Debug(fmt.Sprintf("  Keyfile: %s", fullKeyfilePath))
		}
	}

	return nil
}

func (l *StandardLogic) handleInteractiveConfirmations() error {
	if l.config.IsNonInteractive() {
		l.logger.Debug("Non-interactive mode: skipping confirmations")
		return nil
	}

	confirm, err := l.inputCli.AskConfirmation("Are you sure you want to execute this action? (Y/n)")
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}
	if !confirm {
		l.logger.Info("Operation cancelled by user")
		os.Exit(0)
	}

	confirm, err = l.inputCli.AskConfirmation("Do you want to create the database in the default location? (Y/n)")
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}
	if !confirm {
		l.logger.Info("Custom location requires explicit --database-path flag")
		l.logger.Fatal("Please restart with --database-path flag")
		os.Exit(1)
	}

	if !l.config.GetNoKeyfile() {
		confirm, err = l.inputCli.AskConfirmation("Do you want to protect the database with a keyfile? (Y/n)")
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		if !confirm {
			l.logger.Warn("Keyfile protection recommended for security")
		}
	}

	return nil
}

func (l *StandardLogic) getPassword() error {
	if l.config.GetPassword() != "" {
		l.logger.Debug("Password already set in config")
		return nil
	}

	if password, ok := l.inputEnv.Get("SECRETS_PASSWORD"); ok && password != "" {
		l.logger.Debug("Using password from SECRETS_PASSWORD env var")
		l.config.SetPassword(password)
		return nil
	}

	if !l.config.IsNonInteractive() {
		password, err := l.inputCli.AskPasswordConfirm("Enter your new password: ")
		if err != nil {
			l.logger.Fatal(fmt.Sprintf("Failed to read password: %s", err))
			return err
		}
		l.config.SetPassword(password)
		return nil
	}

	l.logger.Fatal("SECRETS_PASSWORD required in non-interactive mode")
	return fmt.Errorf("SECRETS_PASSWORD required in non-interactive mode")
}

func (l *StandardLogic) calculateDatabasePath() string {
	dbPath := l.config.GetDatabasePath()

	if l.config.IsIgnoreConfigFile() {
		if filepath.IsAbs(dbPath) {
			return dbPath
		}
		cwd, _ := os.Getwd()
		return filepath.Join(cwd, dbPath)
	}

	if filepath.IsAbs(dbPath) {
		return dbPath
	}
	home := os.Getenv("HOME")
	dbName := l.config.GetDatabaseName()
	return filepath.Join(home, ".secrets", dbName, dbPath)
}

func (l *StandardLogic) calculateKeyfilePath() string {
	if l.config.GetNoKeyfile() {
		return ""
	}

	keyfilePath := l.config.GetKeyfile()

	if l.config.IsIgnoreConfigFile() {
		if filepath.IsAbs(keyfilePath) {
			return keyfilePath
		}
		cwd, _ := os.Getwd()
		return filepath.Join(cwd, keyfilePath)
	}

	if filepath.IsAbs(keyfilePath) {
		return keyfilePath
	}
	home := os.Getenv("HOME")
	dbName := l.config.GetDatabaseName()
	return filepath.Join(home, ".secrets", dbName, keyfilePath)
}

func (l *StandardLogic) createDatabase(fullDBPath, fullKeyfilePath string) error {
	l.logger.Debug("Creating database...")

	dbDir := filepath.Dir(fullDBPath)
	if err := l.output.CreateDir(dbDir, 0700); err != nil {
		l.logger.Fatal(fmt.Sprintf("Failed to create database directory: %s", err))
		return err
	}

	if fullKeyfilePath != "" {
		keyfileDir := filepath.Dir(fullKeyfilePath)
		if err := l.output.CreateDir(keyfileDir, 0700); err != nil {
			l.logger.Fatal(fmt.Sprintf("Failed to create keyfile directory: %s", err))
			return err
		}

		if err := l.bd.GenerateKeyfile(fullKeyfilePath); err != nil {
			l.logger.Fatal(fmt.Sprintf("Failed to generate keyfile: %s", err))
			return err
		}
		l.logger.Info(fmt.Sprintf("Generated keyfile: %s", fullKeyfilePath))
	}

	password := l.config.GetPassword()
	dbName := l.config.GetDatabaseName()

	if err := l.bd.CreateDatabase(fullDBPath, password, fullKeyfilePath, dbName); err != nil {
		l.logger.Fatal(fmt.Sprintf("Failed to create database: %s", err))
		return err
	}

	l.logger.Info(fmt.Sprintf("Database created: %s", fullDBPath))
	return nil
}

func (l *StandardLogic) createConfigFile(fullDBPath, fullKeyfilePath string) error {
	if l.config.IsIgnoreConfigFile() {
		l.logger.Info("Skipping config file creation (--ignore-config-file)")
		return nil
	}

	l.logger.Debug("Creating config.yml...")

	// Use configured config path instead of hardcoding
	configPath := l.config.GetConfigPath()
	configDir := filepath.Dir(configPath)

	// Create parent directory if it doesn't exist
	if err := l.output.CreateDir(configDir, 0700); err != nil {
		l.logger.Fatal(fmt.Sprintf("Failed to create config directory: %s", err))
		return err
	}

	// Build new database configuration
	newConfig := l.buildConfigYAML()
	databaseName := l.config.GetDatabaseName()

	// Check if config file already exists
	var finalContent string
	if _, err := os.Stat(configPath); err == nil {
		// Config exists, read current content
		currentContent, err := os.ReadFile(configPath)
		if err != nil {
			l.logger.Fatal(fmt.Sprintf("Failed to read existing config: %s", err))
			return err
		}

		// Check if this database name already exists in config
		if l.configContainsDatabase(string(currentContent), databaseName) {
			l.logger.Info(fmt.Sprintf("Database '%s' already configured in config.yml", databaseName))
			return nil
		}

		// Append new config with separator
		finalContent = string(currentContent) + "---\n" + newConfig
		l.logger.Debug(fmt.Sprintf("Appending database '%s' to existing config", databaseName))
	} else {
		// Config doesn't exist, use new content
		finalContent = newConfig
		l.logger.Debug("Creating new config file")
	}

	if err := l.output.WriteFile(configPath, []byte(finalContent), 0600); err != nil {
		l.logger.Fatal(fmt.Sprintf("Failed to write config file: %s", err))
		return err
	}

	l.logger.Info(fmt.Sprintf("Config created: %s", configPath))
	return nil
}

func (l *StandardLogic) configContainsDatabase(content, dbName string) bool {
	// Simple check: look for 'name: "dbName"' or 'name: dbName' in config
	return strings.Contains(content, fmt.Sprintf("name: \"%s\"", dbName)) ||
		strings.Contains(content, fmt.Sprintf("name: %s", dbName))
}

func (l *StandardLogic) buildConfigYAML() string {
	var sb strings.Builder

	sb.WriteString("database:\n")
	sb.WriteString(fmt.Sprintf("  name: \"%s\"\n", l.config.GetDatabaseName()))
	sb.WriteString(fmt.Sprintf("  path: \"%s\"\n", l.config.GetDatabasePath()))

	if !l.config.GetNoKeyfile() {
		sb.WriteString(fmt.Sprintf("  keyfile: \"%s\"\n", l.config.GetKeyfile()))
	}

	return sb.String()
}
