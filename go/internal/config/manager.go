package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Yohnah/secrets/internal/types"
	"gopkg.in/yaml.v3"
)

// Manager defines the interface for configuration management
type Manager interface {
	GetConfig() (*Config, error)
	CreateDefaultConfig(path string) error
	GetDatabasePath() string
	GetKeyfilePath() string
	ShouldIgnoreConfigFile() bool
	ShouldIgnoreGitProject() bool
}

// Config holds the complete application configuration
type Config struct {
	DatabasePath  string
	KeyfilePath   string
	ConfigPath    string
	Verbose       bool
	NoInteractive bool
	Password      string
	OutputFormat  string
	IgnoreConfig  bool
}

type manager struct {
	globalFlags *types.GlobalFlags
	config      *Config
}

// FileConfig represents the structure of config.yml
type FileConfig struct {
	Database string `yaml:"database"`
	Keyfile  string `yaml:"keyfile"`
}

// NewManager creates a new ConfigManager instance
func NewManager(flags *types.GlobalFlags) Manager {
	return &manager{
		globalFlags: flags,
	}
}

// GetConfig processes and returns the complete configuration
// Applies precedence: FLAGS > CONFIG.YML > ENV VARS > DEFAULTS
func (m *manager) GetConfig() (*Config, error) {
	if m.config != nil {
		return m.config, nil
	}

	config := &Config{}

	// Step 1: Apply DEFAULTS
	config.DatabasePath = ".secrets_yohnah/secrets.kdbx"
	config.KeyfilePath = ".secrets_yohnah/secrets.keyfile"
	config.ConfigPath = ".secrets_yohnah/config.yml"
	config.OutputFormat = "table"
	config.Verbose = false
	config.NoInteractive = false
	config.IgnoreConfig = false
	config.Password = ""

	// Step 2: Read ENV VARS
	if envPassword := os.Getenv("SECRETS_YOHNAH_PASSWORD"); envPassword != "" {
		config.Password = envPassword
	}
	if envDatabase := os.Getenv("SECRETS_YOHNAH_DATABASE"); envDatabase != "" {
		config.DatabasePath = envDatabase
	}
	if envKeyfile := os.Getenv("SECRETS_YOHNAH_KEYFILE"); envKeyfile != "" {
		config.KeyfilePath = envKeyfile
	}
	if envConfig := os.Getenv("SECRETS_YOHNAH_CONFIG"); envConfig != "" {
		config.ConfigPath = envConfig
	}
	if envOutput := os.Getenv("SECRETS_YOHNAH_OUTPUT_FORMAT"); envOutput != "" {
		config.OutputFormat = envOutput
	}
	if envVerbose := os.Getenv("SECRETS_YOHNAH_VERBOSE"); envVerbose == "true" {
		config.Verbose = true
	}

	// Step 3: Read CONFIG.YML (if not ignored)
	if !m.globalFlags.IgnoreConfigFile {
		configPath := config.ConfigPath
		if m.globalFlags.Config != "" {
			configPath = m.globalFlags.Config
		}

		if fileConfig, err := m.readConfigFile(configPath); err == nil {
			if fileConfig.Database != "" {
				config.DatabasePath = fileConfig.Database
			}
			if fileConfig.Keyfile != "" {
				config.KeyfilePath = fileConfig.Keyfile
			}
		}
		// Ignore error if config file doesn't exist
	}

	// Step 4: Apply FLAGS (highest priority)
	if m.globalFlags.Database != "" {
		config.DatabasePath = m.globalFlags.Database
	}
	if m.globalFlags.Keyfile != "" {
		config.KeyfilePath = m.globalFlags.Keyfile
	}
	if m.globalFlags.Config != "" {
		config.ConfigPath = m.globalFlags.Config
	}
	if m.globalFlags.OutputFormat != "" {
		config.OutputFormat = m.globalFlags.OutputFormat
	}
	config.Verbose = m.globalFlags.Verbose
	config.NoInteractive = m.globalFlags.Force
	config.IgnoreConfig = m.globalFlags.IgnoreConfigFile

	// Cache the config
	m.config = config

	return config, nil
}

// readConfigFile reads and parses the config.yml file
func (m *manager) readConfigFile(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var fileConfig FileConfig
	if err := yaml.Unmarshal(data, &fileConfig); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &fileConfig, nil
}

// CreateDefaultConfig creates a default config.yml file with inline format
// dbPath and keyPath should be the paths to write in the config file
func (m *manager) CreateDefaultConfig(path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Check if file already exists
	if _, err := os.Stat(path); err == nil {
		return nil // File already exists, don't overwrite
	}

	// Get current configuration to write the actual paths being used
	config, err := m.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	dbPath := config.DatabasePath
	keyPath := config.KeyfilePath

	// Create inline YAML content
	content := fmt.Sprintf("database: %s\nkeyfile: %s\n", dbPath, keyPath)

	// Write to file
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetDatabasePath returns the database path from configuration
func (m *manager) GetDatabasePath() string {
	config, _ := m.GetConfig()
	if config != nil {
		return config.DatabasePath
	}
	return ".secrets_yohnah/secrets.kdbx"
}

// GetKeyfilePath returns the keyfile path from configuration
func (m *manager) GetKeyfilePath() string {
	config, _ := m.GetConfig()
	if config != nil {
		return config.KeyfilePath
	}
	return ".secrets_yohnah/secrets.keyfile"
}

// ShouldIgnoreConfigFile returns whether config file should be ignored
func (m *manager) ShouldIgnoreConfigFile() bool {
	return m.globalFlags.IgnoreConfigFile
}

// ShouldIgnoreGitProject returns whether git project detection should be ignored
func (m *manager) ShouldIgnoreGitProject() bool {
	return m.globalFlags.IgnoreGitProject
}
