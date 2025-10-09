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
}

// Metadata contains the profile configuration
type Metadata struct {
	Profile            string `yaml:"profile"`
	DefaultEnvironment string `yaml:"default_environment,omitempty"` // Deprecated, will be removed
}

// Outputs represents the outputs section
type Outputs struct {
	Dotenv        []OutputItem `yaml:"dotenv,omitempty"`
	Dotnet        []OutputItem `yaml:"dotnet,omitempty"`
	SpringBoot    []OutputItem `yaml:"spring_boot,omitempty"`
	Terraform     []OutputItem `yaml:"terraform,omitempty"`
	Shell         []ShellItem  `yaml:"shell,omitempty"`
	Ansible       []OutputItem `yaml:"ansible,omitempty"`
	DockerCompose []OutputItem `yaml:"docker_compose,omitempty"`
	Kubernetes    []OutputItem `yaml:"kubernetes,omitempty"`
	Custom        []CustomItem `yaml:"custom,omitempty"`
}

// OutputItem represents a basic output item with file and environment
type OutputItem struct {
	File        string `yaml:"file"`
	Environment string `yaml:"environment"`
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
