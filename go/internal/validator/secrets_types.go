package validator

// SecretsConfig represents the complete secrets.yml configuration with multiple profiles
type SecretsConfig struct {
	Profiles []Profile
}

// Profile represents a single profile document in secrets.yml
type Profile struct {
	Metadata     Metadata          `yaml:"metadata"`
	Environments map[string][]Item `yaml:"environments"`
	Outputs      Outputs           `yaml:"outputs,omitempty"`
	Volumes      Volumes           `yaml:"volumes,omitempty"`
}

// Metadata contains the profile configuration
type Metadata struct {
	Profile            string            `yaml:"profile"`
	DefaultEnvironment string            `yaml:"default_environment,omitempty"` // Deprecated, will be removed
	Basedirs           map[string]string `yaml:"basedirs,omitempty"`            // environment -> volume-name mapping
}

// Outputs represents the outputs section as a list of output items
type Outputs []OutputItem

// Volumes represents the volumes section as a list of volume items
type Volumes []VolumeItem

// OutputItem represents a single output configuration
type OutputItem struct {
	File        string `yaml:"file"`
	Environment string `yaml:"environment"`
	Format      string `yaml:"format"`
	SectionBy   string `yaml:"section_by,omitempty"` // Optional, defaults to "none"
	Template    string `yaml:"template,omitempty"`   // Optional, used for custom format
}

// VolumeItem represents a single volume configuration
type VolumeItem struct {
	Name      string `yaml:"name"`
	MountPath string `yaml:"mount_path"`
	Type      string `yaml:"type"`
}

// ShellItem represents a shell output item with additional format field
type ShellItem struct {
	File        string `yaml:"file"`
	Environment string `yaml:"environment"`
	Format      string `yaml:"format"`
}

// CustomItem represents a custom output item with template field
type CustomItem struct {
	File        string `yaml:"file"`
	Environment string `yaml:"environment"`
	Template    string `yaml:"template"`
}

// Item represents a secret item within an environment
type Item struct {
	Name  string `yaml:"name"`
	Type  string `yaml:"type"`
	Entry string `yaml:"entry"`
	Key   string `yaml:"key"`
}

// ValidationError represents a validation error with context
type ValidationError struct {
	Type        string // Type of error (e.g., "duplicate_profile", "missing_field")
	Location    string // Where the error occurred (e.g., "profile:myapp", "env:production")
	Description string // Human-readable description
	Suggestion  string // How to fix it
}

// Error implements the error interface
func (e *ValidationError) Error() string {
	return e.Description
}
