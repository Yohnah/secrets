package logicmanager

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yohnah/secrets/internal/bdmanager"
	"github.com/Yohnah/secrets/internal/configmanager"
	"github.com/Yohnah/secrets/internal/loggermanager"
	"github.com/Yohnah/secrets/internal/outputmanager"
	"gopkg.in/yaml.v3"
)

type LogicManager interface {
	ExecuteInit() error
}

type StandardLogicManager struct {
	config configmanager.Config
	bd     bdmanager.BD
	output outputmanager.Output
	logger loggermanager.Logger
}

func NewLogicManager(
	config configmanager.Config,
	bd bdmanager.BD,
	output outputmanager.Output,
	logger loggermanager.Logger,
) LogicManager {
	return &StandardLogicManager{
		config: config,
		bd:     bd,
		output: output,
		logger: logger,
	}
}

type DatabaseConfig struct {
	Database struct {
		Name    string `yaml:"name"`
		Path    string `yaml:"path"`
		Keyfile string `yaml:"keyfile,omitempty"`
	} `yaml:"database"`
}

func (l *StandardLogicManager) updateConfigFile(configPath, dbName, dbPath, keyfilePath string) error {
	var existingConfigs []DatabaseConfig

	// Read existing config if it exists
	if fileData, err := os.ReadFile(configPath); err == nil {
		// Parse multiple YAML documents separated by ---
		decoder := yaml.NewDecoder(strings.NewReader(string(fileData)))
		for {
			var cfg DatabaseConfig
			if err := decoder.Decode(&cfg); err != nil {
				if err.Error() == "EOF" {
					break
				}
				return fmt.Errorf("failed to parse existing config: %w", err)
			}
			existingConfigs = append(existingConfigs, cfg)
		}
	}

	// Check if configuration with this database.name already exists
	found := false
	for i := range existingConfigs {
		if existingConfigs[i].Database.Name == dbName {
			// Update existing
			existingConfigs[i].Database.Path = dbPath
			if keyfilePath != "" {
				existingConfigs[i].Database.Keyfile = keyfilePath
			} else {
				existingConfigs[i].Database.Keyfile = ""
			}
			found = true
			break
		}
	}

	// If it doesn't exist, add new
	if !found {
		newConfig := DatabaseConfig{}
		newConfig.Database.Name = dbName
		newConfig.Database.Path = dbPath
		if keyfilePath != "" {
			newConfig.Database.Keyfile = keyfilePath
		}
		existingConfigs = append(existingConfigs, newConfig)
	}

	// Serialize all documents separated by ---
	var buffer strings.Builder
	for i, cfg := range existingConfigs {
		if i > 0 {
			buffer.WriteString("---\n")
		}
		yamlData, err := yaml.Marshal(&cfg)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}
		buffer.Write(yamlData)
	}

	// Write complete file
	if err := l.output.WriteFile(configPath, []byte(buffer.String()), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func (l *StandardLogicManager) ExecuteInit() error {
	defer l.config.ClearPassword()

	// 1. Get initial configuration
	dbPath := l.config.GetDatabasePath()
	dbName := l.config.GetDatabaseName()
	keyfilePath := l.config.GetKeyfile()
	ignoreConfigFile := l.config.GetIgnoreConfigFile()
	forceRecreate := l.config.GetForceRecreate()
	noCreateDatabase := l.config.GetNoCreateDatabase()
	noKeyfile := l.config.GetNoKeyfile()
	isNonInteractive := l.config.IsNonInteractive()

	if noKeyfile {
		keyfilePath = ""
	}

	// 2. Early detection: check if database already exists
	var resolvedDBPath string
	if !ignoreConfigFile {
		baseDir := filepath.Join(l.config.GetHomeDir(), ".secrets")
		dbDir := filepath.Join(baseDir, dbName)
		if !filepath.IsAbs(dbPath) {
			resolvedDBPath = filepath.Join(dbDir, dbPath)
		} else {
			resolvedDBPath = dbPath
		}
	} else {
		resolvedDBPath = dbPath
	}

	if !noCreateDatabase && l.bd.DatabaseExists(resolvedDBPath) && !forceRecreate {
		return fmt.Errorf("database already exists: %s (use --force-recreate to recreate)", resolvedDBPath)
	}

	// 3. Interactive mode: request confirmations BEFORE any operation
	if !isNonInteractive {
		if err := l.config.HandleInteractiveConfirmationsForInit(); err != nil {
			return err
		}
		// After confirmations, update flags that may have changed
		noKeyfile = l.config.GetNoKeyfile()
		if noKeyfile {
			keyfilePath = ""
		}
	}

	// 4. Get password AFTER confirmations
	if err := l.config.ObtainPassword(); err != nil {
		return err
	}

	// 5. Get password and final configuration
	password := l.config.GetPassword()
	configPath := l.config.GetConfigPath()

	// 5. Execute operations according to configuration
	if !ignoreConfigFile {
		baseDir := filepath.Join(l.config.GetHomeDir(), ".secrets")
		dbDir := filepath.Join(baseDir, dbName)
		if !filepath.IsAbs(dbPath) {
			resolvedDBPath = filepath.Join(dbDir, dbPath)
		} else {
			resolvedDBPath = dbPath
		}
		resolvedKeyfilePath := keyfilePath
		if keyfilePath != "" && !filepath.IsAbs(keyfilePath) {
			resolvedKeyfilePath = filepath.Join(dbDir, keyfilePath)
		}

		if forceRecreate && l.bd.DatabaseExists(resolvedDBPath) {
			l.logger.Info(fmt.Sprintf("Deleting existing database: %s", resolvedDBPath))
			if err := l.bd.DeleteDatabase(resolvedDBPath); err != nil {
				return fmt.Errorf("failed to delete existing database: %w", err)
			}
		}

		if !noCreateDatabase {
			if !filepath.IsAbs(dbPath) {
				if err := l.output.CreateDir(dbDir, 0700); err != nil {
					return fmt.Errorf("failed to create database directory: %w", err)
				}
			}

			if keyfilePath != "" {
				l.logger.Info(fmt.Sprintf("Generating keyfile: %s", resolvedKeyfilePath))
				if err := l.bd.GenerateKeyfile(resolvedKeyfilePath); err != nil {
					return fmt.Errorf("failed to generate keyfile: %w", err)
				}
			}

			l.logger.Info(fmt.Sprintf("Creating KeePass database: %s", resolvedDBPath))
			if err := l.bd.CreateDatabase(resolvedDBPath, password, resolvedKeyfilePath, dbName); err != nil {
				return fmt.Errorf("failed to create database: %w", err)
			}
		}

		l.logger.Info(fmt.Sprintf("Writing config file: %s", configPath))
		if err := l.updateConfigFile(configPath, dbName, dbPath, keyfilePath); err != nil {
			return fmt.Errorf("failed to update config file: %w", err)
		}

		l.logger.Info(fmt.Sprintf("✓ Initialization completed successfully"))
		l.logger.Info(fmt.Sprintf("  Database: %s", resolvedDBPath))
		if keyfilePath != "" {
			l.logger.Info(fmt.Sprintf("  Keyfile: %s", resolvedKeyfilePath))
		}
		l.logger.Info(fmt.Sprintf("  Config: %s", configPath))
	} else {
		if !noCreateDatabase {
			resolvedDBPath := dbPath
			resolvedKeyfilePath := keyfilePath

			if forceRecreate && l.bd.DatabaseExists(resolvedDBPath) {
				l.logger.Info(fmt.Sprintf("Deleting existing database: %s", resolvedDBPath))
				if err := l.bd.DeleteDatabase(resolvedDBPath); err != nil {
					return fmt.Errorf("failed to delete existing database: %w", err)
				}
			}

			if keyfilePath != "" {
				l.logger.Info(fmt.Sprintf("Generating keyfile: %s", resolvedKeyfilePath))
				if err := l.bd.GenerateKeyfile(resolvedKeyfilePath); err != nil {
					return fmt.Errorf("failed to generate keyfile: %w", err)
				}
			}

			l.logger.Info(fmt.Sprintf("Creating KeePass database: %s", resolvedDBPath))
			if err := l.bd.CreateDatabase(resolvedDBPath, password, resolvedKeyfilePath, dbName); err != nil {
				return fmt.Errorf("failed to create database: %w", err)
			}

			l.logger.Info(fmt.Sprintf("✓ Initialization completed successfully"))
			l.logger.Info(fmt.Sprintf("  Database: %s", resolvedDBPath))
			if keyfilePath != "" {
				l.logger.Info(fmt.Sprintf("  Keyfile: %s", resolvedKeyfilePath))
			}
		} else {
			l.logger.Info("✓ Initialization completed (no database created)")
		}
	}

	return nil
}
