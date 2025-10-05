package config

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/Yohnah/secrets/internal/types"
	"github.com/Yohnah/secrets/internal/validator"
	"gopkg.in/yaml.v3"
)

//go:embed templates/config.tpl.yml
var configTemplate string

// Manager defines the interface for configuration management
type Manager interface {
	GetConfig() (*Config, error)
	CreateDefaultConfig(path string) error
	CreateDefaultConfigWithNoCreate(path string, noCreateDatabase bool) error
	GetDatabasePath() string
	GetKeyfilePath() string
	ShouldIgnoreConfigFile() bool
	ShouldIgnoreGitProject() bool
}

// Config holds the complete application configuration
type Config struct {
	DatabasePath     string
	KeyfilePath      string
	ConfigPath       string
	Verbose          bool
	NoInteractive    bool
	Password         string
	OutputFormat     string
	IgnoreConfig     bool
	NoCreateDatabase bool
}

type manager struct {
	globalFlags *types.GlobalFlags
	config      *Config
	validator   validator.ValidatorManager
}

// FileConfig represents the structure of config.yml
type FileConfig struct {
	Database         string `yaml:"database"`
	Keyfile          string `yaml:"keyfile"`
	NoCreateDatabase *bool  `yaml:"no_create_database,omitempty"`
}

// NewManager creates a new ConfigManager instance
func NewManager(flags *types.GlobalFlags, validator validator.ValidatorManager) Manager {
	manager := &manager{
		globalFlags: flags,
		validator:   validator,
	}

	// Validate template at startup
	if err := validator.ValidateTemplate(configTemplate); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Config template validation failed: %v\n", err)
	}

	return manager
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
	config.NoCreateDatabase = false

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
	if envVerbose := os.Getenv("SECRETS_YOHNAH_VERBOSE"); envVerbose == "true" {
		config.Verbose = true
	}

	// Step 3: Read CONFIG.YML (if not ignored)
	if !m.globalFlags.IgnoreConfigFile {
		configPath := config.ConfigPath
		if m.globalFlags.Config != "" {
			configPath = m.globalFlags.Config
		}

		fileConfig, err := m.readConfigFile(configPath)
		if err != nil {
			// Only ignore "file not found" errors
			// Any other error (validation, parsing, etc.) is critical
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
			// File doesn't exist - continue with defaults
		} else {
			// File exists and is valid - apply config
			if fileConfig.Database != "" {
				config.DatabasePath = fileConfig.Database
			}
			if fileConfig.Keyfile != "" {
				config.KeyfilePath = fileConfig.Keyfile
			}
			if fileConfig.NoCreateDatabase != nil {
				config.NoCreateDatabase = *fileConfig.NoCreateDatabase
			}
		}
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
	config.Verbose = m.globalFlags.Verbose
	config.NoInteractive = m.globalFlags.Force
	config.IgnoreConfig = m.globalFlags.IgnoreConfigFile

	// Cache the config
	m.config = config

	return config, nil
}

// readConfigFile reads and parses the config.yml file
func (m *manager) readConfigFile(path string) (*FileConfig, error) {
	// Check if file exists first
	data, err := os.ReadFile(path)
	if err != nil {
		// If file doesn't exist, return error (caller will handle it)
		return nil, err
	}

	// Validate config file structure ONLY if file exists
	if err := m.validator.ValidateConfigFile(path); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
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
	return m.CreateDefaultConfigWithNoCreate(path, false)
}

// CreateDefaultConfigWithNoCreate creates a default config.yml file with inline format
// If noCreateDatabase is true, the no_create_database field will be set to true
func (m *manager) CreateDefaultConfigWithNoCreate(path string, noCreateDatabase bool) error {
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

	// Prepare template data
	type TemplateData struct {
		Database             string
		Keyfile              string
		NoCreateDatabaseLine string
	}

	noCreateLine := "# no_create_database: true"
	if noCreateDatabase {
		noCreateLine = "no_create_database: true"
	}

	data := TemplateData{
		Database:             dbPath,
		Keyfile:              keyPath,
		NoCreateDatabaseLine: noCreateLine,
	}

	// Parse and execute template
	tmpl, err := template.New("config").Parse(configTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse config template: %w", err)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute config template: %w", err)
	}

	content := buf.String()

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
