package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
// Following SRP - Single Responsibility Principle: only handles configuration structure
type Config struct {
	DatabasePath string `yaml:"database_path"`
	KeyfilePath  string `yaml:"keyfile_path"`
}

// ConfigOptions holds all possible configuration sources for precedence resolution
// Following Open/Closed Principle - extensible for new configuration sources
type ConfigOptions struct {
	// Global flags - highest precedence
	DatabaseFlag string
	KeyfileFlag  string

	// Command-specific flags - same precedence as global flags
	CommandFlags map[string]interface{}

	// Config file path
	ConfigPath string

	// Base path for relative path resolution (typically .secrets_yohnah)
	BasePath string
}

// ConfigManager handles configuration file operations and precedence resolution
// Following SRP and DIP - Dependency Inversion Principle
// ALWAYS applies precedence: FLAGS > config.yml > environment variables > defaults
type ConfigManager interface {
	Load(options ConfigOptions) (*Config, error)
	Save(configPath string, config *Config) error
	ResolvePath(basePath, configuredPath string) string
}

// FileConfigManager implements ConfigManager
type FileConfigManager struct{}

// NewConfigManager creates a new config manager
// Following DIP - factory function
func NewConfigManager() ConfigManager {
	return &FileConfigManager{}
}

// Load reads and resolves configuration applying complete precedence ALWAYS:
// FLAGS (global + command-specific) > config.yml > environment variables > defaults
func (m *FileConfigManager) Load(options ConfigOptions) (*Config, error) {
	// Start with defaults
	config := &Config{
		DatabasePath: "secrets.kdbx",    // Default relative to base path
		KeyfilePath:  "secrets.keyfile", // Default relative to base path
	}

	// 1. Apply environment variables (overwrites defaults)
	if envDB := os.Getenv("SECRETS_YOHNAH_DATABASE_PATH"); envDB != "" {
		config.DatabasePath = envDB
	}
	if envKey := os.Getenv("SECRETS_YOHNAH_KEYFILE_PATH"); envKey != "" {
		config.KeyfilePath = envKey
	}

	// 2. Load from config file if exists (overwrites env vars)
	if options.ConfigPath != "" {
		if _, err := os.Stat(options.ConfigPath); err == nil {
			data, err := os.ReadFile(options.ConfigPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}

			var fileConfig Config
			if err := yaml.Unmarshal(data, &fileConfig); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}

			// Only override if values are not empty in config file
			if fileConfig.DatabasePath != "" {
				config.DatabasePath = fileConfig.DatabasePath
			}
			if fileConfig.KeyfilePath != "" {
				config.KeyfilePath = fileConfig.KeyfilePath
			}
		}
	}

	// 3. Apply global flags (highest precedence - overwrites everything)
	if options.DatabaseFlag != "" {
		config.DatabasePath = options.DatabaseFlag
	}
	if options.KeyfileFlag != "" {
		config.KeyfilePath = options.KeyfileFlag
	}

	// 4. Apply command-specific flags (same precedence as global flags)
	if options.CommandFlags != nil {
		if dbFlag, exists := options.CommandFlags["database"]; exists {
			if dbStr, ok := dbFlag.(string); ok && dbStr != "" {
				config.DatabasePath = dbStr
			}
		}
		if keyfileFlag, exists := options.CommandFlags["keyfile"]; exists {
			if keyfileStr, ok := keyfileFlag.(string); ok && keyfileStr != "" {
				config.KeyfilePath = keyfileStr
			}
		}
	}

	// 5. Resolve all paths relative to base path
	if options.BasePath != "" {
		config.DatabasePath = m.ResolvePath(options.BasePath, config.DatabasePath)
		config.KeyfilePath = m.ResolvePath(options.BasePath, config.KeyfilePath)
	}

	return config, nil
}

// Save writes configuration to YAML file
func (m *FileConfigManager) Save(configPath string, config *Config) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// ResolvePath resolves a path relative to basePath if not absolute
// Relative paths are considered relative to basePath (typically .secrets_yohnah)
func (m *FileConfigManager) ResolvePath(basePath, configuredPath string) string {
	// If absolute path, use as-is
	if filepath.IsAbs(configuredPath) {
		return configuredPath
	}

	// If relative path or just filename, resolve relative to basePath
	return filepath.Join(basePath, configuredPath)
}
