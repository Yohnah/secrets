package validator

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ReadAndValidateSecretsYML reads and validates a secrets.yml file
// Returns the parsed configuration and a list of all validation errors found
func (m *manager) ReadAndValidateSecretsYML(filePath string) (*SecretsConfig, []error) {
	var errors []error

	// Step 1: Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		errors = append(errors, fmt.Errorf("secrets.yml not found at: %s\nSuggestions:\n  - Create with: secrets show template > %s\n  - Specify path: -s /path/to/file.yml", filePath, filePath))
		return nil, errors
	}

	// Step 2: Read file content
	data, err := os.ReadFile(filePath)
	if err != nil {
		errors = append(errors, fmt.Errorf("failed to read secrets.yml: %w", err))
		return nil, errors
	}

	// Step 3: Parse YAML multi-document
	profiles, parseErrors := parseMultiDocumentYAML(data)
	if len(parseErrors) > 0 {
		errors = append(errors, parseErrors...)
		return nil, errors
	}

	// Step 4: Validate all profiles
	validationErrors := validateSecretsConfig(profiles)
	if len(validationErrors) > 0 {
		errors = append(errors, validationErrors...)
		return nil, errors
	}

	// Step 5: Return successful configuration
	config := &SecretsConfig{
		Profiles: profiles,
	}

	return config, nil
}

// parseMultiDocumentYAML parses a YAML file with multiple documents (separated by ---)
func parseMultiDocumentYAML(data []byte) ([]Profile, []error) {
	var profiles []Profile
	var errors []error

	decoder := yaml.NewDecoder(strings.NewReader(string(data)))

	docIndex := 0
	for {
		var profile Profile
		err := decoder.Decode(&profile)
		if err != nil {
			// EOF is expected when no more documents
			if err.Error() == "EOF" {
				break
			}
			errors = append(errors, fmt.Errorf("failed to parse YAML document %d: %w", docIndex+1, err))
			return nil, errors
		}

		profiles = append(profiles, profile)
		docIndex++
	}

	// At least one profile must exist
	if len(profiles) == 0 {
		errors = append(errors, fmt.Errorf("secrets.yml must contain at least one profile"))
		return nil, errors
	}

	return profiles, nil
}

// validateSecretsConfig validates the entire secrets configuration
func validateSecretsConfig(profiles []Profile) []error {
	var errors []error

	// Validate profiles
	profileErrors := validateProfiles(profiles)
	errors = append(errors, profileErrors...)

	// Validate each profile's environments and items
	for _, profile := range profiles {
		envErrors := validateEnvironments(profile)
		errors = append(errors, envErrors...)

		itemErrors := validateItems(profile)
		errors = append(errors, itemErrors...)

		outputErrors := validateOutputs(profile)
		errors = append(errors, outputErrors...)
	}

	return errors
}

// validateProfiles validates profile-level rules
func validateProfiles(profiles []Profile) []error {
	var errors []error

	// Track profile names (case-insensitive)
	profileNames := make(map[string]int) // lowercase name -> document index

	for i, profile := range profiles {
		// Validate metadata exists
		if profile.Metadata.Profile == "" {
			errors = append(errors, fmt.Errorf("profile %d: metadata.profile is required and cannot be empty", i+1))
		}

		if profile.Metadata.DefaultEnvironment != "" {
			errors = append(errors, fmt.Errorf("profile %d ('%s'): metadata.default_environment is no longer supported, please remove it from your secrets.yml", i+1, profile.Metadata.Profile))
		} // Check for duplicate profile names (case-insensitive)
		profileNameLower := strings.ToLower(profile.Metadata.Profile)
		if existingIndex, exists := profileNames[profileNameLower]; exists {
			errors = append(errors, fmt.Errorf("duplicate profile name found: '%s' (document %d conflicts with document %d, case-insensitive match)", profile.Metadata.Profile, i+1, existingIndex+1))
		} else {
			profileNames[profileNameLower] = i
		}

		// Validate that environments section exists
		if len(profile.Environments) == 0 {
			errors = append(errors, fmt.Errorf("profile '%s': must have at least one environment defined", profile.Metadata.Profile))
		}
	}

	return errors
}

// validateEnvironments validates environment-level rules
func validateEnvironments(profile Profile) []error {
	var errors []error

	// Track environment names (case-insensitive) within this profile
	envNames := make(map[string]bool)

	for envName := range profile.Environments {
		envNameLower := strings.ToLower(envName)

		// Check for duplicate environment names (case-insensitive)
		if envNames[envNameLower] {
			errors = append(errors, fmt.Errorf("profile '%s': duplicate environment name '%s' (case-insensitive match)", profile.Metadata.Profile, envName))
		}
		envNames[envNameLower] = true
	}

	return errors
}

// validateItems validates item-level rules for all environments in a profile
func validateItems(profile Profile) []error {
	var errors []error

	for envName, items := range profile.Environments {
		// Track item names (case-insensitive) within this environment
		itemNames := make(map[string]bool)

		for itemIndex, item := range items {
			// Validate all required fields
			fieldErrors := validateItemFields(item, profile.Metadata.Profile, envName, itemIndex)
			errors = append(errors, fieldErrors...)

			// Check for duplicate item names (case-insensitive) within environment
			if item.Name != "" {
				itemNameLower := strings.ToLower(item.Name)
				if itemNames[itemNameLower] {
					errors = append(errors, fmt.Errorf("profile '%s', environment '%s': duplicate item name '%s' (case-insensitive match)", profile.Metadata.Profile, envName, item.Name))
				}
				itemNames[itemNameLower] = true
			}
		}
	}

	return errors
}

// validateItemFields validates individual item fields
func validateItemFields(item Item, profileName, envName string, itemIndex int) []error {
	var errors []error

	location := fmt.Sprintf("profile '%s', environment '%s', item %d", profileName, envName, itemIndex+1)

	// Validate 'name' field
	if item.Name == "" {
		errors = append(errors, fmt.Errorf("%s: field 'name' is required", location))
	} else {
		// Validate name format: alphanumeric, underscore, hyphen (no spaces, no special chars)
		if !isValidItemName(item.Name) {
			errors = append(errors, fmt.Errorf("%s: field 'name' ('%s') contains invalid characters (only alphanumeric, underscore, and hyphen allowed)", location, item.Name))
		}
	}

	// Validate 'type' field
	if item.Type == "" {
		errors = append(errors, fmt.Errorf("%s: field 'type' is required", location))
	} else {
		validTypes := map[string]bool{
			"envvar":    true,
			"text":      true,
			"ssh_agent": true,
		}
		if !validTypes[item.Type] {
			errors = append(errors, fmt.Errorf("%s: field 'type' ('%s') must be one of: envvar, text, ssh_agent", location, item.Type))
		}
	}

	// Validate 'entry' field
	if item.Entry == "" {
		errors = append(errors, fmt.Errorf("%s: field 'entry' is required", location))
	} else {
		if !strings.HasPrefix(item.Entry, "/") {
			errors = append(errors, fmt.Errorf("%s: field 'entry' ('%s') must start with '/'", location, item.Entry))
		}
		// Additional validation: no double slashes, no trailing slash (except for root)
		if strings.Contains(item.Entry, "//") {
			errors = append(errors, fmt.Errorf("%s: field 'entry' ('%s') cannot contain double slashes", location, item.Entry))
		}
		if len(item.Entry) > 1 && strings.HasSuffix(item.Entry, "/") {
			errors = append(errors, fmt.Errorf("%s: field 'entry' ('%s') cannot end with '/' (except root)", location, item.Entry))
		}
		if item.Entry == "/" {
			errors = append(errors, fmt.Errorf("%s: field 'entry' cannot be just '/' (root path)", location))
		}
	}

	// Validate 'key' field
	if item.Key == "" {
		errors = append(errors, fmt.Errorf("%s: field 'key' is required", location))
	}

	return errors
}

// isValidItemName checks if an item name contains only allowed characters
// Allowed: A-Z, a-z, 0-9, underscore (_), hyphen (-)
func isValidItemName(name string) bool {
	pattern := `^[A-Za-z0-9_-]+$`
	matched, _ := regexp.MatchString(pattern, name)
	return matched
}

// validateOutputs validates the outputs section of a profile
func validateOutputs(profile Profile) []error {
	var errors []error
	outputs := profile.Outputs

	// Track all file paths to ensure uniqueness
	filePaths := make(map[string]bool)

	// Helper to check file uniqueness
	checkFileUniqueness := func(file, outputType string, index int) {
		if file == "" {
			errors = append(errors, fmt.Errorf("profile '%s': outputs.%s[%d]: field 'file' is required", profile.Metadata.Profile, outputType, index))
			return
		}
		if filePaths[file] {
			errors = append(errors, fmt.Errorf("profile '%s': outputs.%s[%d]: file '%s' is already used in another output (files must be unique)", profile.Metadata.Profile, outputType, index, file))
		} else {
			filePaths[file] = true
		}
	}

	// Helper to check environment exists
	checkEnvironmentExists := func(environment, outputType string, index int) {
		if environment == "" {
			errors = append(errors, fmt.Errorf("profile '%s': outputs.%s[%d]: field 'environment' is required", profile.Metadata.Profile, outputType, index))
			return
		}
		if _, exists := profile.Environments[environment]; !exists {
			errors = append(errors, fmt.Errorf("profile '%s': outputs.%s[%d]: environment '%s' does not exist in environments section", profile.Metadata.Profile, outputType, index, environment))
		}
	}

	// Validate dotenv
	if len(outputs.Dotenv) > 0 {
		for i, item := range outputs.Dotenv {
			checkFileUniqueness(item.File, "dotenv", i)
			checkEnvironmentExists(item.Environment, "dotenv", i)
		}
	}

	// Validate dotnet
	if len(outputs.Dotnet) > 0 {
		for i, item := range outputs.Dotnet {
			checkFileUniqueness(item.File, "dotnet", i)
			checkEnvironmentExists(item.Environment, "dotnet", i)
		}
	}

	// Validate spring_boot
	if len(outputs.SpringBoot) > 0 {
		for i, item := range outputs.SpringBoot {
			checkFileUniqueness(item.File, "spring_boot", i)
			checkEnvironmentExists(item.Environment, "spring_boot", i)
		}
	}

	// Validate terraform
	if len(outputs.Terraform) > 0 {
		for i, item := range outputs.Terraform {
			checkFileUniqueness(item.File, "terraform", i)
			checkEnvironmentExists(item.Environment, "terraform", i)
		}
	}

	// Validate shell (has additional format field)
	if len(outputs.Shell) > 0 {
		validFormats := map[string]bool{
			"bash":       true,
			"zsh":        true,
			"fish":       true,
			"sh":         true,
			"powershell": true,
		}
		for i, item := range outputs.Shell {
			checkFileUniqueness(item.File, "shell", i)
			checkEnvironmentExists(item.Environment, "shell", i)

			if item.Format == "" {
				errors = append(errors, fmt.Errorf("profile '%s': outputs.shell[%d]: field 'format' is required", profile.Metadata.Profile, i))
			} else if !validFormats[item.Format] {
				errors = append(errors, fmt.Errorf("profile '%s': outputs.shell[%d]: format '%s' is invalid (must be: bash, zsh, fish, sh, powershell)", profile.Metadata.Profile, i, item.Format))
			}
		}
	}

	// Validate ansible
	if len(outputs.Ansible) > 0 {
		for i, item := range outputs.Ansible {
			checkFileUniqueness(item.File, "ansible", i)
			checkEnvironmentExists(item.Environment, "ansible", i)
		}
	}

	// Validate docker_compose
	if len(outputs.DockerCompose) > 0 {
		for i, item := range outputs.DockerCompose {
			checkFileUniqueness(item.File, "docker_compose", i)
			checkEnvironmentExists(item.Environment, "docker_compose", i)
		}
	}

	// Validate kubernetes
	if len(outputs.Kubernetes) > 0 {
		for i, item := range outputs.Kubernetes {
			checkFileUniqueness(item.File, "kubernetes", i)
			checkEnvironmentExists(item.Environment, "kubernetes", i)
		}
	}

	// Validate custom (has additional template field, allows template reuse)
	if len(outputs.Custom) > 0 {
		for i, item := range outputs.Custom {
			checkFileUniqueness(item.File, "custom", i)
			checkEnvironmentExists(item.Environment, "custom", i)

			if item.Template == "" {
				errors = append(errors, fmt.Errorf("profile '%s': outputs.custom[%d]: field 'template' is required", profile.Metadata.Profile, i))
			} else {
				// Check if template file exists
				if _, err := os.Stat(item.Template); os.IsNotExist(err) {
					errors = append(errors, fmt.Errorf("profile '%s': outputs.custom[%d]: template file '%s' does not exist", profile.Metadata.Profile, i, item.Template))
				}
			}
		}
	}

	return errors
}
