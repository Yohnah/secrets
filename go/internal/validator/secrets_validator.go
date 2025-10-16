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

		volumeErrors := validateVolumes(profile)
		errors = append(errors, volumeErrors...)
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
		// Validate name format: alphanumeric, underscore, hyphen, dot (no spaces, no special chars)
		if !isValidItemName(item.Name) {
			errors = append(errors, fmt.Errorf("%s: field 'name' ('%s') contains invalid characters (only alphanumeric, underscore, hyphen, and dot allowed)", location, item.Name))
		}
	}

	// Validate 'type' field
	if item.Type == "" {
		errors = append(errors, fmt.Errorf("%s: field 'type' is required", location))
	} else {
		validTypes := map[string]bool{
			"envvar": true,
			"sshkey": true,
		}
		if !validTypes[item.Type] {
			errors = append(errors, fmt.Errorf("%s: field 'type' ('%s') must be one of: envvar, sshkey", location, item.Type))
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
// Allowed: A-Z, a-z, 0-9, underscore (_), hyphen (-), dot (.)
func isValidItemName(name string) bool {
	pattern := `^[A-Za-z0-9_.-]+$`
	matched, _ := regexp.MatchString(pattern, name)
	return matched
}

// validateOutputs validates the outputs section (list format)
func validateOutputs(profile Profile) []error {
	var errors []error

	// Track file names to check for duplicates
	fileMap := make(map[string]bool)

	for i, output := range profile.Outputs {
		// Validate required fields
		if output.File == "" {
			errors = append(errors, fmt.Errorf("profile '%s': outputs[%d]: 'file' is required", profile.Metadata.Profile, i))
		}
		if output.Environment == "" {
			errors = append(errors, fmt.Errorf("profile '%s': outputs[%d]: 'environment' is required", profile.Metadata.Profile, i))
		}
		if output.Format == "" {
			errors = append(errors, fmt.Errorf("profile '%s': outputs[%d]: 'format' is required", profile.Metadata.Profile, i))
		}

		// Check for duplicate files
		if output.File != "" {
			if fileMap[output.File] {
				errors = append(errors, fmt.Errorf("profile '%s': outputs[%d]: duplicate file '%s'", profile.Metadata.Profile, i, output.File))
			}
			fileMap[output.File] = true
		}

		// Validate environment exists
		if output.Environment != "" {
			envExists := false
			for envName := range profile.Environments {
				if envName == output.Environment {
					envExists = true
					break
				}
			}
			if !envExists {
				errors = append(errors, fmt.Errorf("profile '%s': outputs[%d] (file: '%s', format: '%s'): environment '%s' not found", profile.Metadata.Profile, i, output.File, output.Format, output.Environment))
			}
		}

		// Validate format
		validFormats := []string{"dotenv", "dotnet", "spring_boot", "terraform", "shell", "ansible", "docker-compose", "k8s", "ini", "toml", "yaml", "json", "custom"}
		formatValid := false
		for _, f := range validFormats {
			if output.Format == f {
				formatValid = true
				break
			}
		}
		if !formatValid {
			errors = append(errors, fmt.Errorf("profile '%s': outputs[%d]: invalid format '%s'", profile.Metadata.Profile, i, output.Format))
		}

		// Validate section_by for structured formats
		structuredFormats := []string{"ini", "toml", "yaml"}
		isStructured := false
		for _, f := range structuredFormats {
			if output.Format == f {
				isStructured = true
				break
			}
		}

		if isStructured {
			// Default to "none" if not specified
			sectionBy := output.SectionBy
			if sectionBy == "" {
				sectionBy = "none"
			}

			// Validate section_by value
			validSectionBy := []string{"environment", "default", "none"}
			sectionByValid := false
			for _, sb := range validSectionBy {
				if sectionBy == sb {
					sectionByValid = true
					break
				}
			}

			// Check for custom: prefix
			if strings.HasPrefix(sectionBy, "custom:") {
				if len(sectionBy) <= 7 { // "custom:" is 7 chars
					errors = append(errors, fmt.Errorf("profile '%s': outputs[%d]: custom section name cannot be empty", profile.Metadata.Profile, i))
				}
				sectionByValid = true
			}

			if !sectionByValid {
				errors = append(errors, fmt.Errorf("profile '%s': outputs[%d]: invalid section_by '%s'", profile.Metadata.Profile, i, sectionBy))
			}
		}

		// Special validation for shell format (if still used)
		if output.Format == "shell" {
			// Shell might need format field, but in new format, perhaps not.
			// For now, skip special validation.
		}

		// Special validation for custom format
		if output.Format == "custom" {
			if output.Template == "" {
				errors = append(errors, fmt.Errorf("profile '%s': outputs[%d]: 'template' is required for custom format", profile.Metadata.Profile, i))
			}
		}
	}

	return errors
}

// validateVolumes validates the volumes section (list format)
func validateVolumes(profile Profile) []error {
	var errors []error

	// Track volume names to check for duplicates
	nameMap := make(map[string]bool)

	for i, volume := range profile.Volumes {
		// Validate required fields
		if volume.Name == "" {
			errors = append(errors, fmt.Errorf("profile '%s': volumes[%d]: 'name' is required", profile.Metadata.Profile, i))
		}
		if volume.MountPath == "" {
			errors = append(errors, fmt.Errorf("profile '%s': volumes[%d]: 'mount_path' is required", profile.Metadata.Profile, i))
		}
		if volume.Type == "" {
			errors = append(errors, fmt.Errorf("profile '%s': volumes[%d]: 'type' is required", profile.Metadata.Profile, i))
		}

		// Check for duplicate names
		if volume.Name != "" {
			if nameMap[volume.Name] {
				errors = append(errors, fmt.Errorf("profile '%s': volumes[%d]: duplicate name '%s'", profile.Metadata.Profile, i, volume.Name))
			}
			nameMap[volume.Name] = true
		}

		// Validate volume type (only "dir" for now)
		if volume.Type != "dir" {
			errors = append(errors, fmt.Errorf("profile '%s': volumes[%d]: invalid type '%s' (only 'dir' is currently supported)", profile.Metadata.Profile, i, volume.Type))
		}
	}

	// Validate basedirs references to volumes
	if profile.Metadata.Basedirs != nil {
		for envName, volumeName := range profile.Metadata.Basedirs {
			found := false
			for _, volume := range profile.Volumes {
				if volume.Name == volumeName {
					found = true
					break
				}
			}
			if !found {
				errors = append(errors, fmt.Errorf("profile '%s': basedirs['%s'] references volume '%s' which is not defined in volumes section", profile.Metadata.Profile, envName, volumeName))
			}
		}
	}

	return errors
}
