package importer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseFile reads a file and extracts variables based on its format.
// The format is detected by file extension (.json, .yml, .yaml, .env, .properties, .toml, .tfvars, .ini).
// If decodeBase64 is true, all values are treated as base64-encoded and decoded.
// Returns a map of variable names to values, or an error if parsing fails.
// Supports nested structures (flattened with dot notation) and Kubernetes Secret detection.
func ParseFile(filePath string, decodeBase64 bool) (map[string]string, error) {
	// Read the entire file content into memory for processing
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	// Detect format by analyzing the file extension (converted to lowercase for case-insensitive matching)
	fileExtension := strings.ToLower(filepath.Ext(filePath))

	var parsedVariables map[string]string

	// Route to appropriate parser based on file extension
	// Each parser handles format-specific syntax and structure
	switch fileExtension {
	case ".json":
		parsedVariables, err = parseJSON(fileContent)
	case ".yml", ".yaml":
		parsedVariables, err = parseYAML(fileContent)
	case ".env", ".dotenv":
		parsedVariables, err = parseDotenv(fileContent)
	case ".properties":
		parsedVariables, err = parseProperties(fileContent)
	case ".toml":
		parsedVariables, err = parseTOML(fileContent)
	case ".tfvars":
		parsedVariables, err = parseTerraform(fileContent)
	case ".ini":
		parsedVariables, err = parseINI(fileContent)
	default:
		return nil, fmt.Errorf("unsupported file format: %s (file: %s)", fileExtension, filePath)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse file %s: %w", filePath, err)
	}

	// If base64 decoding is requested, decode all values that appear to be base64-encoded
	// This allows importing files with encoded secrets (common in Kubernetes manifests)
	if decodeBase64 {
		parsedVariables = decodeBase64Values(parsedVariables)
	}

	return parsedVariables, nil
}

// parseJSON parses JSON files
// Supports nested structures like {"production": {"KEY": "value"}} or flat {"KEY": "value"}
func parseJSON(content []byte) (map[string]string, error) {
	var data interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	variables := make(map[string]string)
	flattenJSON(data, "", variables)
	return variables, nil
}

// flattenJSON recursively flattens nested JSON structures into a flat key-value map.
// Nested objects are flattened using dot notation (e.g., "parent.child.key": "value").
// Only string, number, and boolean values are preserved; arrays and nulls are ignored.
// The prefix accumulates the path as we traverse deeper into the structure.
func flattenJSON(data interface{}, currentPrefix string, flattenedResult map[string]string) {
	switch value := data.(type) {
	case map[string]interface{}:
		// For objects, recursively process each key-value pair
		for objectKey, objectValue := range value {
			fullKey := objectKey
			if currentPrefix != "" {
				fullKey = currentPrefix + "." + objectKey
			}
			flattenJSON(objectValue, fullKey, flattenedResult)
		}
	case string:
		// For string values, add to result if we have a valid key path
		if currentPrefix != "" {
			flattenedResult[currentPrefix] = value
		}
	case float64, int, bool:
		// For primitive values (numbers, booleans), convert to string and add to result
		if currentPrefix != "" {
			flattenedResult[currentPrefix] = fmt.Sprint(value)
		}
	}
}

// parseYAML parses YAML files
// Supports plain YAML, nested structures, and Kubernetes secrets
func parseYAML(content []byte) (map[string]string, error) {
	var data interface{}
	if err := yaml.Unmarshal(content, &data); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}

	variables := make(map[string]string)

	// Check if it's a Kubernetes Secret
	if isKubernetesSecret(data) {
		return parseKubernetesSecret(data)
	}

	// Otherwise, flatten the YAML structure
	flattenYAML(data, "", variables)
	return variables, nil
}

// isKubernetesSecret checks if the YAML is a Kubernetes Secret
func isKubernetesSecret(data interface{}) bool {
	if m, ok := data.(map[string]interface{}); ok {
		apiVersion, hasAPIVersion := m["apiVersion"]
		kind, hasKind := m["kind"]
		return hasAPIVersion && hasKind && kind == "Secret" && strings.HasPrefix(fmt.Sprint(apiVersion), "v")
	}
	return false
}

// parseKubernetesSecret extracts variables from Kubernetes Secret data section
func parseKubernetesSecret(data interface{}) (map[string]string, error) {
	m, ok := data.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid Kubernetes Secret structure")
	}

	dataSection, ok := m["data"]
	if !ok {
		return make(map[string]string), nil // Empty secret
	}

	dataMap, ok := dataSection.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid Kubernetes Secret data section")
	}

	variables := make(map[string]string)
	for key, value := range dataMap {
		variables[key] = fmt.Sprint(value)
	}

	return variables, nil
}

// flattenYAML recursively flattens nested YAML structures
func flattenYAML(data interface{}, prefix string, result map[string]string) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			newKey := key
			if prefix != "" {
				newKey = prefix + "." + key
			}
			flattenYAML(value, newKey, result)
		}
	case string:
		if prefix != "" {
			result[prefix] = v
		}
	case int, float64, bool:
		if prefix != "" {
			result[prefix] = fmt.Sprint(v)
		}
	}
}

// parseDotenv parses .env files
// Supports KEY=value and KEY="value" formats
func parseDotenv(content []byte) (map[string]string, error) {
	variables := make(map[string]string)
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split by first = sign
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		value = strings.Trim(value, `"'`)

		variables[key] = value
	}

	return variables, nil
}

// parseProperties parses Java .properties files
// Similar to dotenv but supports different comment styles
func parseProperties(content []byte) (map[string]string, error) {
	variables := make(map[string]string)
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments (# or !)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		// Split by first = or : sign
		var key, value string
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			key = strings.TrimSpace(parts[0])
			value = strings.TrimSpace(parts[1])
		} else if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			key = strings.TrimSpace(parts[0])
			value = strings.TrimSpace(parts[1])
		} else {
			continue
		}

		variables[key] = value
	}

	return variables, nil
}

// parseTOML parses TOML files
// For now, we treat TOML similarly to INI with sections
func parseTOML(content []byte) (map[string]string, error) {
	// For simplicity, we'll parse TOML as INI-like structure
	// A full TOML parser would require external library
	return parseINI(content)
}

// parseTerraform parses Terraform .tfvars files
// Similar to properties but with Terraform-specific syntax
func parseTerraform(content []byte) (map[string]string, error) {
	variables := make(map[string]string)
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Split by = sign
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		value = strings.Trim(value, `"'`)

		variables[key] = value
	}

	return variables, nil
}

// parseINI parses INI files
// Supports sections [section] and key=value pairs
func parseINI(content []byte) (map[string]string, error) {
	variables := make(map[string]string)
	lines := strings.Split(string(content), "\n")
	currentSection := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			continue
		}

		// Split by = sign
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		value = strings.Trim(value, `"'`)

		// If we're in a section, prefix the key with section name
		if currentSection != "" {
			key = currentSection + "." + key
		}

		variables[key] = value
	}

	return variables, nil
}

// decodeBase64Values attempts to decode base64 values in the map
func decodeBase64Values(variables map[string]string) map[string]string {
	decoded := make(map[string]string)

	for key, value := range variables {
		// Try to decode base64
		decodedBytes, err := base64.StdEncoding.DecodeString(value)
		if err == nil {
			// Successfully decoded
			decoded[key] = string(decodedBytes)
		} else {
			// Not base64 or decode failed, keep original
			decoded[key] = value
		}
	}

	return decoded
}
