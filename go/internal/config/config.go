package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
// Following SRP - Single Responsibility Principle: only handles configuration structure
// Includes all configuration: paths, flags, and runtime options
type Config struct {
	// Database configuration
	DatabasePath string `yaml:"database_path"`
	KeyfilePath  string `yaml:"keyfile_path"`

	// Runtime flags (not persisted to config.yml)
	Verbose  bool // Verbose output mode
	Force    bool // Force mode (skip confirmations)
	Extended bool // Extended output mode (detailed information)

	// Command-specific configuration (extensible)
	CommandFlags map[string]interface{} // Additional command-specific flags
}

// ConfigOptions holds all possible configuration sources for precedence resolution
// Following Open/Closed Principle - extensible for new configuration sources
type ConfigOptions struct {
	// Global flags - highest precedence
	DatabaseFlag string
	KeyfileFlag  string
	VerboseFlag  bool
	ForceFlag    bool
	ExtendedFlag bool

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
		Verbose:      false,             // Default: no verbose output
		Force:        false,             // Default: require confirmations
		CommandFlags: make(map[string]interface{}),
	}

	// 1. Apply environment variables (overwrites defaults)
	if envDB := os.Getenv("SECRETS_YOHNAH_DATABASE_PATH"); envDB != "" {
		config.DatabasePath = envDB
	}
	if envKey := os.Getenv("SECRETS_YOHNAH_KEYFILE_PATH"); envKey != "" {
		config.KeyfilePath = envKey
	}
	if envVerbose := os.Getenv("SECRETS_YOHNAH_VERBOSE"); envVerbose == "true" || envVerbose == "1" {
		config.Verbose = true
	}
	if envForce := os.Getenv("SECRETS_YOHNAH_FORCE"); envForce == "true" || envForce == "1" {
		config.Force = true
	}

	// 2. Load from config file if exists (overwrites env vars)
	// Note: config.yml only stores DatabasePath and KeyfilePath, not runtime flags
	if options.ConfigPath != "" {
		if _, err := os.Stat(options.ConfigPath); err == nil {
			data, err := os.ReadFile(options.ConfigPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}

			var fileConfig struct {
				DatabasePath string `yaml:"database_path"`
				KeyfilePath  string `yaml:"keyfile_path"`
			}
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
	// Verbose, Force, and Extended flags are boolean, so we check if they were explicitly set
	// By convention, if these flags are passed, they override previous values
	config.Verbose = options.VerboseFlag
	config.Force = options.ForceFlag
	config.Extended = options.ExtendedFlag

	// 4. Apply command-specific flags (same precedence as global flags)
	if options.CommandFlags != nil {
		// Store command-specific flags for later use
		config.CommandFlags = options.CommandFlags

		// Also check if command-specific flags override global settings
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
		if verboseFlag, exists := options.CommandFlags["verbose"]; exists {
			if verboseBool, ok := verboseFlag.(bool); ok {
				config.Verbose = verboseBool
			}
		}
		if forceFlag, exists := options.CommandFlags["force"]; exists {
			if forceBool, ok := forceFlag.(bool); ok {
				config.Force = forceBool
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
// Only persists DatabasePath and KeyfilePath (not runtime flags like Verbose/Force)
func (m *FileConfigManager) Save(configPath string, config *Config) error {
	// Create a struct with only persistable fields
	persistable := struct {
		DatabasePath string `yaml:"database_path"`
		KeyfilePath  string `yaml:"keyfile_path"`
	}{
		DatabasePath: config.DatabasePath,
		KeyfilePath:  config.KeyfilePath,
	}

	data, err := yaml.Marshal(persistable)
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
