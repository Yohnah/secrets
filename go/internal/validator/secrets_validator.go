package validator

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// SecretsValidator validates secrets.yml file structure and content according to project criteria
type SecretsValidator interface {
	ValidateFile(content []byte) (*SecretsConfig, error)
	ValidateStructure(config *SecretsConfig) error
}

// SecretsConfig represents the complete structure of secrets.yml
type SecretsConfig struct {
	Metadata     MetadataSection     `yaml:",inline"`
	Environments EnvironmentsSection `yaml:",inline"`
	Reserved     interface{}         `yaml:",inline"`
}

// MetadataSection represents the first section of secrets.yml
type MetadataSection struct {
	Profile            string `yaml:"profile"`
	DefaultEnvironment string `yaml:"default_environment"`
}

// EnvironmentsSection represents the second section of secrets.yml
type EnvironmentsSection map[string][]SecretItem

// SecretItem represents an individual secret item within an environment
type SecretItem struct {
	Name  string `yaml:"name"`
	Type  string `yaml:"type"`
	Entry string `yaml:"entry"`
	Key   string `yaml:"key"`
}

// secretsValidator implements SecretsValidator interface
type secretsValidator struct{}

// NewSecretsValidator creates a new SecretsValidator instance
func NewSecretsValidator() SecretsValidator {
	return &secretsValidator{}
}

// ValidateFile parses and validates the complete secrets.yml file
func (v *secretsValidator) ValidateFile(content []byte) (*SecretsConfig, error) {
	// Split YAML into three sections using --- separator
	sections := strings.Split(string(content), "---")
	if len(sections) != 3 {
		return nil, fmt.Errorf("secrets.yml must have exactly 3 sections separated by '---', found %d sections", len(sections))
	}

	config := &SecretsConfig{}

	// Parse Section 1: Metadata
	if err := yaml.Unmarshal([]byte(sections[0]), &config.Metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata section: %w", err)
	}

	// Parse Section 2: Environments
	if err := yaml.Unmarshal([]byte(sections[1]), &config.Environments); err != nil {
		return nil, fmt.Errorf("failed to parse environments section: %w", err)
	}

	// Parse Section 3: Reserved (for future use)
	if strings.TrimSpace(sections[2]) != "" {
		if err := yaml.Unmarshal([]byte(sections[2]), &config.Reserved); err != nil {
			return nil, fmt.Errorf("failed to parse reserved section: %w", err)
		}
	}

	// Validate structure and business rules
	if err := v.ValidateStructure(config); err != nil {
		return nil, err
	}

	return config, nil
}

// ValidateStructure validates the structure and business rules of the parsed config
func (v *secretsValidator) ValidateStructure(config *SecretsConfig) error {
	// Validate metadata section
	if err := v.validateMetadata(&config.Metadata); err != nil {
		return fmt.Errorf("metadata validation failed: %w", err)
	}

	// Validate environments section
	if err := v.validateEnvironments(config.Environments); err != nil {
		return fmt.Errorf("environments validation failed: %w", err)
	}

	// Validate that default_environment exists in environments
	if err := v.validateDefaultEnvironmentExists(config); err != nil {
		return err
	}

	return nil
}

// validateMetadata validates the metadata section
func (v *secretsValidator) validateMetadata(metadata *MetadataSection) error {
	// Validate profile field
	if metadata.Profile == "" {
		return fmt.Errorf("profile field is required and cannot be empty")
	}

	if strings.TrimSpace(metadata.Profile) != metadata.Profile {
		return fmt.Errorf("profile field cannot have leading or trailing whitespace")
	}

	if strings.Contains(metadata.Profile, " ") {
		return fmt.Errorf("profile field cannot contain spaces")
	}

	// Validate default_environment field
	if metadata.DefaultEnvironment == "" {
		return fmt.Errorf("default_environment field is required and cannot be empty")
	}

	if strings.TrimSpace(metadata.DefaultEnvironment) != metadata.DefaultEnvironment {
		return fmt.Errorf("default_environment field cannot have leading or trailing whitespace")
	}

	if strings.Contains(metadata.DefaultEnvironment, " ") {
		return fmt.Errorf("default_environment field cannot contain spaces")
	}

	return nil
}

// validateEnvironments validates the environments section
func (v *secretsValidator) validateEnvironments(environments EnvironmentsSection) error {
	if len(environments) == 0 {
		return fmt.Errorf("at least one environment must be defined")
	}

	// Validate environment names for uniqueness and format
	for envName := range environments {
		if strings.TrimSpace(envName) != envName {
			return fmt.Errorf("environment name '%s' cannot have leading or trailing whitespace", envName)
		}

		if strings.Contains(envName, " ") {
			return fmt.Errorf("environment name '%s' cannot contain spaces", envName)
		}

		if envName == "" {
			return fmt.Errorf("environment name cannot be empty")
		}
	}

	// Validate each environment's items
	for envName, items := range environments {
		if err := v.validateEnvironmentItems(envName, items); err != nil {
			return err
		}
	}

	return nil
}

// validateEnvironmentItems validates items within a single environment
func (v *secretsValidator) validateEnvironmentItems(envName string, items []SecretItem) error {
	if len(items) == 0 {
		return fmt.Errorf("environment '%s' must have at least one item", envName)
	}

	// Track uniqueness within this environment
	itemNames := make(map[string]bool)

	for i, item := range items {
		// Validate required fields
		if err := v.validateSecretItem(envName, i, &item); err != nil {
			return err
		}

		// Check name uniqueness within environment
		if itemNames[item.Name] {
			return fmt.Errorf("environment '%s': duplicate item name '%s' found", envName, item.Name)
		}
		itemNames[item.Name] = true

		// Note: Entry path duplication is allowed - multiple items can reference the same entry
		// This enables using the same secret for different purposes (envvar, text, ssh_agent)
	}

	return nil
}

// validateSecretItem validates an individual secret item
func (v *secretsValidator) validateSecretItem(envName string, index int, item *SecretItem) error {
	// Validate name field
	if item.Name == "" {
		return fmt.Errorf("environment '%s' item %d: name field is required and cannot be empty", envName, index)
	}

	// Validate type field
	validTypes := map[string]bool{
		"envvar":    true,
		"text":      true,
		"ssh_agent": true,
	}
	if !validTypes[item.Type] {
		return fmt.Errorf("environment '%s' item '%s': invalid type '%s', must be one of: envvar, text, ssh_agent", envName, item.Name, item.Type)
	}

	// Validate entry field
	if item.Entry == "" {
		return fmt.Errorf("environment '%s' item '%s': entry field is required and cannot be empty", envName, item.Name)
	}

	// Validate key field
	if item.Key == "" {
		return fmt.Errorf("environment '%s' item '%s': key field is required and cannot be empty", envName, item.Name)
	}

	return nil
}

// validateDefaultEnvironmentExists validates that the default_environment exists in environments
func (v *secretsValidator) validateDefaultEnvironmentExists(config *SecretsConfig) error {
	if _, exists := config.Environments[config.Metadata.DefaultEnvironment]; !exists {
		return fmt.Errorf("default_environment '%s' does not exist in environments section", config.Metadata.DefaultEnvironment)
	}
	return nil
}

// normalizeEntryPath normalizes entry paths for comparison ("ENTRY" and "/ENTRY" are the same)
func (v *secretsValidator) normalizeEntryPath(entry string) string {
	if !strings.HasPrefix(entry, "/") {
		return "/" + entry
	}
	return entry
}
