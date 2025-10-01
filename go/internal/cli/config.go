package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the configuration structure
type Config struct {
	DatabasePath string `yaml:"database_path"`
	KeyfilePath  string `yaml:"keyfile_path"`
}

// ConfigManager interface follows ISP - Interface Segregation Principle
type ConfigManager interface {
	LoadConfig(configPath string) (*Config, error)
	SaveConfig(configPath string, config *Config) error
	GetDefaultConfig() *Config
	ResolveAbsolutePath(basePath, relativePath string) string
	ValidateConfigPaths(config *Config, basePath string) error
}

// DefaultConfigManager follows SRP - Single Responsibility for config management
type DefaultConfigManager struct {
	logger Logger
}

// NewConfigManager factory function follows DIP - Dependency Inversion Principle
func NewConfigManager(logger Logger) ConfigManager {
	return &DefaultConfigManager{
		logger: logger,
	}
}

// GetDefaultConfig returns the default configuration
func (c *DefaultConfigManager) GetDefaultConfig() *Config {
	return &Config{
		DatabasePath: "./secrets.kdbx",
		KeyfilePath:  "./secrets.keyfile",
	}
}

// LoadConfig loads configuration from YAML file
func (c *DefaultConfigManager) LoadConfig(configPath string) (*Config, error) {
	c.logger.Debug("Loading config from: " + configPath)
	
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}
	
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("error parsing config YAML: %v", err)
	}
	
	c.logger.Debug("Config loaded successfully")
	return &config, nil
}

// SaveConfig saves configuration to YAML file
func (c *DefaultConfigManager) SaveConfig(configPath string, config *Config) error {
	c.logger.Debug("Saving config to: " + configPath)
	
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("error marshaling config to YAML: %v", err)
	}
	
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("error writing config file: %v", err)
	}
	
	c.logger.Debug("Config saved successfully")
	return nil
}

// ResolveAbsolutePath resolves relative paths relative to basePath
func (c *DefaultConfigManager) ResolveAbsolutePath(basePath, relativePath string) string {
	if filepath.IsAbs(relativePath) {
		return relativePath
	}
	
	// Handle relative paths like "./secrets.kdbx" -> basePath/secrets.kdbx
	if relativePath[:2] == "./" {
		return filepath.Join(basePath, relativePath[2:])
	}
	
	return filepath.Join(basePath, relativePath)
}

// ValidateConfigPaths validates that the paths in config exist
func (c *DefaultConfigManager) ValidateConfigPaths(config *Config, basePath string) error {
	c.logger.Debug("Validating config paths")
	
	// Resolve absolute paths
	dbPath := c.ResolveAbsolutePath(basePath, config.DatabasePath)
	keyfilePath := c.ResolveAbsolutePath(basePath, config.KeyfilePath)
	
	// Check if database file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		c.logger.Debug("Database file does not exist: " + dbPath)
		return fmt.Errorf("database file does not exist: %s", dbPath)
	}
	
	// Check if keyfile exists
	if _, err := os.Stat(keyfilePath); os.IsNotExist(err) {
		c.logger.Debug("Keyfile does not exist: " + keyfilePath)
		return fmt.Errorf("keyfile does not exist: %s", keyfilePath)
	}
	
	c.logger.Debug("Config paths validation successful")
	return nil
}