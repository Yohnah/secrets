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

if profile.Metadata.DefaultEnvironment == "" {
errors = append(errors, fmt.Errorf("profile %d ('%s'): metadata.default_environment is required and cannot be empty", i+1, profile.Metadata.Profile))
}

// Check for duplicate profile names (case-insensitive)
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

// Check that default_environment exists
defaultEnvLower := strings.ToLower(profile.Metadata.DefaultEnvironment)
defaultEnvExists := false

for envName := range profile.Environments {
envNameLower := strings.ToLower(envName)

// Check if this is the default environment
if envNameLower == defaultEnvLower {
defaultEnvExists = true
}

// Check for duplicate environment names (case-insensitive)
if envNames[envNameLower] {
errors = append(errors, fmt.Errorf("profile '%s': duplicate environment name '%s' (case-insensitive match)", profile.Metadata.Profile, envName))
}
envNames[envNameLower] = true
}

// Validate that default_environment exists in environments
if !defaultEnvExists {
errors = append(errors, fmt.Errorf("profile '%s': default_environment '%s' does not exist in environments", profile.Metadata.Profile, profile.Metadata.DefaultEnvironment))
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
