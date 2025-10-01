package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
	"github.com/Yohnah/secrets/internal/logger"
)

// Config represents the configuration structure
type Config struct {
	DatabasePath string `yaml:"database_path"`
	KeyfilePath  string `yaml:"keyfile_path"`
}

// Manager interface follows ISP - Interface Segregation Principle
// Separates configuration management concerns
type Manager interface {
	LoadConfig(configPath string) (*Config, error)
	SaveConfig(config *Config, configPath string) error
	CreateDefaultConfig(configPath string) error
}

// DefaultManager implements Manager interface
// Follows SRP - Single Responsibility Principle: only handles config operations
type DefaultManager struct {
	logger logger.Logger
}

// NewManager creates a new config manager
// Follows DIP - Dependency Inversion Principle: depends on Logger abstraction
func NewManager(logger logger.Logger) Manager {
	return &DefaultManager{
		logger: logger,
	}
}

// LoadConfig loads configuration from file
func (c *DefaultManager) LoadConfig(configPath string) (*Config, error) {
	c.logger.Debug("Loading config from: " + configPath)
	
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}
	
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}
	
	c.logger.Debug("Config loaded successfully")
	return &config, nil
}

// SaveConfig saves configuration to file
func (c *DefaultManager) SaveConfig(config *Config, configPath string) error {
	c.logger.Debug("Saving config to: " + configPath)
	
	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}
	
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}
	
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}
	
	c.logger.Debug("Config saved successfully")
	return nil
}

// CreateDefaultConfig creates a default configuration file
func (c *DefaultManager) CreateDefaultConfig(configPath string) error {
	c.logger.Debug("Creating default config at: " + configPath)
	
	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}
	
	// Create default config content with comments
	configContent := `# Secrets Yohnah Configuration
# This file contains the default configuration for the secrets CLI tool
#
# Configuration precedence:
# 1. Command line flags (highest priority)
# 2. Environment variables
# 3. This config file (lowest priority)
#
# You can customize these values according to your needs

# Path to the KeePass database file (relative to .secrets_yohnah directory)
database_path: secrets.kdbx

# Path to the KeePass keyfile (required, relative to .secrets_yohnah directory)
keyfile_path: secrets.keyfile
`
	
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write default config: %v", err)
	}
	
	c.logger.Debug("Default config created successfully")
	return nil
}