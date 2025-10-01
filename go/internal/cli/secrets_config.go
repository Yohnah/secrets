package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SecretsConfig represents the complete structure of secrets.yml
type SecretsConfig struct {
	Metadata     MetadataSection             `yaml:"metadata"`
	Environments map[string][]EnvironmentItem `yaml:",inline"`
}

// MetadataWrapper represents the first document structure with metadata key
type MetadataWrapper struct {
	Metadata MetadataSection `yaml:"metadata"`
}

// MetadataSection represents the metadata content
type MetadataSection struct {
	Profile            string `yaml:"profile"`
	DefaultEnvironment string `yaml:"default_environment"`
}

// EnvironmentItem represents an item within an environment
type EnvironmentItem struct {
	Name  string `yaml:"name"`
	Entry string `yaml:"entry"`
	Key   string `yaml:"key"`
	Type  string `yaml:"type"`
}

// SecretsConfigManager interface follows ISP - Interface Segregation Principle
type SecretsConfigManager interface {
	LoadSecretsConfig(configPath string) (*SecretsConfig, error)
	ValidateSecretsConfig(config *SecretsConfig) error
	FindSecretsConfigFile(projectRoot string) (string, error)
}

// DefaultSecretsConfigManager follows SRP - Single Responsibility for secrets.yml operations
type DefaultSecretsConfigManager struct {
	logger Logger
}

// NewSecretsConfigManager factory function follows DIP - Dependency Inversion Principle
func NewSecretsConfigManager(logger Logger) SecretsConfigManager {
	return &DefaultSecretsConfigManager{
		logger: logger,
	}
}

// FindSecretsConfigFile locates the secrets.yml file in the project root
func (s *DefaultSecretsConfigManager) FindSecretsConfigFile(projectRoot string) (string, error) {
	s.logger.Debug("Looking for secrets.yml in project root: " + projectRoot)
	
	configPath := filepath.Join(projectRoot, "secrets.yml")
	
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return "", fmt.Errorf("secrets.yml not found in project root: %s", projectRoot)
	}
	
	s.logger.Debug("Found secrets.yml: " + configPath)
	return configPath, nil
}

// LoadSecretsConfig loads and validates the secrets.yml file
func (s *DefaultSecretsConfigManager) LoadSecretsConfig(configPath string) (*SecretsConfig, error) {
	s.logger.Debug("Loading secrets configuration: " + configPath)
	
	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("secrets configuration file not found: %s", configPath)
	}
	
	// Open file
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open secrets configuration: %v", err)
	}
	defer file.Close()
	
	// Create YAML decoder to handle multiple documents
	decoder := yaml.NewDecoder(file)
	
	// Parse first document (metadata section)
	var metadataWrapper MetadataWrapper
	if err := decoder.Decode(&metadataWrapper); err != nil {
		return nil, fmt.Errorf("failed to parse metadata section (document 1): %v", err)
	}
	metadata := metadataWrapper.Metadata
	s.logger.Debug(fmt.Sprintf("Parsed metadata: Profile='%s', DefaultEnv='%s'", metadata.Profile, metadata.DefaultEnvironment))
	
	// Parse second document (environments section)
	var environments map[string][]EnvironmentItem
	if err := decoder.Decode(&environments); err != nil {
		return nil, fmt.Errorf("failed to parse environments section (document 2): %v", err)
	}
	s.logger.Debug(fmt.Sprintf("Parsed %d environments", len(environments)))
	
	// Debug: let's see what we actually parsed
	for envName, items := range environments {
		s.logger.Debug(fmt.Sprintf("Environment '%s' has %d items", envName, len(items)))
	}
	
	// Create config object
	config := &SecretsConfig{
		Metadata:     metadata,
		Environments: environments,
	}
	
	// Validate the loaded configuration
	if err := s.ValidateSecretsConfig(config); err != nil {
		return nil, fmt.Errorf("secrets configuration validation failed: %v", err)
	}
	
	s.logger.Success("Secrets configuration loaded and validated successfully")
	return config, nil
}

// validateYAMLStructure is no longer needed as yaml.Decoder handles multiple documents properly
// This function is kept for potential future use but is currently not called
func (s *DefaultSecretsConfigManager) validateYAMLStructure(content string) error {
	// The yaml.Decoder handles document structure validation automatically
	return nil
}

// ValidateSecretsConfig validates the structure and content of the secrets configuration
func (s *DefaultSecretsConfigManager) ValidateSecretsConfig(config *SecretsConfig) error {
	s.logger.Debug("Validating secrets configuration structure")
	
	// Validate metadata section
	if err := s.validateMetadata(&config.Metadata); err != nil {
		return fmt.Errorf("metadata validation failed: %v", err)
	}
	
	// Validate environments section
	if err := s.validateEnvironments(config.Environments, config.Metadata.DefaultEnvironment); err != nil {
		return fmt.Errorf("environments validation failed: %v", err)
	}
	
	s.logger.Debug("Secrets configuration validation passed")
	return nil
}

// validateMetadata validates the metadata section
func (s *DefaultSecretsConfigManager) validateMetadata(metadata *MetadataSection) error {
	// Validate profile
	if metadata.Profile == "" {
		return fmt.Errorf("profile cannot be empty")
	}
	
	if strings.TrimSpace(metadata.Profile) != metadata.Profile {
		return fmt.Errorf("profile cannot have leading or trailing whitespace")
	}
	
	// Validate default_environment
	if metadata.DefaultEnvironment == "" {
		return fmt.Errorf("default_environment cannot be empty")
	}
	
	if strings.Contains(metadata.DefaultEnvironment, " ") {
		return fmt.Errorf("default_environment cannot contain spaces: '%s'", metadata.DefaultEnvironment)
	}
	
	if strings.TrimSpace(metadata.DefaultEnvironment) != metadata.DefaultEnvironment {
		return fmt.Errorf("default_environment cannot have leading or trailing whitespace")
	}
	
	return nil
}

// validateEnvironments validates the environments section
func (s *DefaultSecretsConfigManager) validateEnvironments(environments map[string][]EnvironmentItem, defaultEnv string) error {
	if len(environments) == 0 {
		return fmt.Errorf("at least one environment must be defined")
	}
	
	// Check that default environment exists
	if _, exists := environments[defaultEnv]; !exists {
		return fmt.Errorf("default_environment '%s' is not defined in environments section", defaultEnv)
	}
	
	// Validate each environment
	for envName, items := range environments {
		if err := s.validateEnvironmentName(envName); err != nil {
			return fmt.Errorf("invalid environment name '%s': %v", envName, err)
		}
		
		if len(items) == 0 {
			return fmt.Errorf("environment '%s' cannot be empty", envName)
		}
		
		// Validate each item in the environment
		for i, item := range items {
			if err := s.validateEnvironmentItem(&item, envName, i); err != nil {
				return fmt.Errorf("invalid item %d in environment '%s': %v", i+1, envName, err)
			}
		}
	}
	
	return nil
}

// validateEnvironmentName validates environment names
func (s *DefaultSecretsConfigManager) validateEnvironmentName(envName string) error {
	if envName == "" {
		return fmt.Errorf("environment name cannot be empty")
	}
	
	if strings.Contains(envName, " ") {
		return fmt.Errorf("environment name cannot contain spaces")
	}
	
	if strings.TrimSpace(envName) != envName {
		return fmt.Errorf("environment name cannot have leading or trailing whitespace")
	}
	
	// Environment names should be valid identifiers (alphanumeric, underscore, hyphen)
	validName := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)
	if !validName.MatchString(envName) {
		return fmt.Errorf("environment name must start with a letter and contain only letters, numbers, underscores, and hyphens")
	}
	
	return nil
}

// validateEnvironmentItem validates individual environment items
func (s *DefaultSecretsConfigManager) validateEnvironmentItem(item *EnvironmentItem, envName string, index int) error {
	// Validate name
	if item.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	
	if strings.TrimSpace(item.Name) != item.Name {
		return fmt.Errorf("name cannot have leading or trailing whitespace")
	}
	
	// Validate entry
	if item.Entry == "" {
		return fmt.Errorf("entry cannot be empty")
	}
	
	if strings.TrimSpace(item.Entry) != item.Entry {
		return fmt.Errorf("entry cannot have leading or trailing whitespace")
	}
	
	// Validate entry path format (if it contains /)
	if strings.Contains(item.Entry, "/") {
		if err := s.validateEntryPath(item.Entry); err != nil {
			return fmt.Errorf("invalid entry path: %v", err)
		}
	}
	
	// Validate key
	if item.Key == "" {
		return fmt.Errorf("key cannot be empty")
	}
	
	if strings.TrimSpace(item.Key) != item.Key {
		return fmt.Errorf("key cannot have leading or trailing whitespace")
	}
	
	// Validate type
	validTypes := []string{"envvar", "ssh_agent"}
	if item.Type == "" {
		return fmt.Errorf("type cannot be empty")
	}
	
	typeValid := false
	for _, validType := range validTypes {
		if item.Type == validType {
			typeValid = true
			break
		}
	}
	
	if !typeValid {
		return fmt.Errorf("type must be one of: %s (found: '%s')", strings.Join(validTypes, ", "), item.Type)
	}
	
	return nil
}

// validateEntryPath validates KeePass entry paths
func (s *DefaultSecretsConfigManager) validateEntryPath(entryPath string) error {
	// Entry path should start with /
	if !strings.HasPrefix(entryPath, "/") {
		return fmt.Errorf("entry path must start with '/'")
	}
	
	// Entry path should not end with / (unless it's just "/")
	if len(entryPath) > 1 && strings.HasSuffix(entryPath, "/") {
		return fmt.Errorf("entry path cannot end with '/'")
	}
	
	// Split path and validate each segment
	segments := strings.Split(entryPath[1:], "/") // Remove leading /
	
	for i, segment := range segments {
		if segment == "" {
			return fmt.Errorf("entry path cannot contain empty segments (double slashes)")
		}
		
		if strings.TrimSpace(segment) != segment {
			return fmt.Errorf("path segment '%s' cannot have leading or trailing whitespace", segment)
		}
		
		// Last segment is the entry name, others are group names
		if i == len(segments)-1 {
			// Validate entry name
			if len(segment) == 0 {
				return fmt.Errorf("entry name cannot be empty")
			}
		} else {
			// Validate group name
			if len(segment) == 0 {
				return fmt.Errorf("group name cannot be empty")
			}
		}
	}
	
	return nil
}