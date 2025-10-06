package output

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Manager defines the interface for output operations
type Manager interface {
	OutputRaw(content string) error
	Output(data interface{}, format string) error
}

// manager implements the Manager interface
type manager struct{}

// NewManager creates a new output manager
func NewManager() Manager {
	return &manager{}
}

// OutputRaw outputs raw content to stdout
func (m *manager) OutputRaw(content string) error {
	fmt.Print(content)
	return nil
}

// Output formats and outputs data according to the specified format
// Supported formats: json, yaml, table
func (m *manager) Output(data interface{}, format string) error {
	switch format {
	case "json":
		return m.outputJSON(data)
	case "yaml", "yml":
		return m.outputYAML(data)
	case "table", "":
		return m.outputTable(data)
	default:
		return fmt.Errorf("unsupported output format: %s (supported: json, yaml, table)", format)
	}
}

// outputJSON outputs data in JSON format with pretty printing
func (m *manager) outputJSON(data interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}
	return nil
}

// outputYAML outputs data in YAML format
func (m *manager) outputYAML(data interface{}) error {
	encoder := yaml.NewEncoder(os.Stdout)
	encoder.SetIndent(2)
	defer encoder.Close()

	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode YAML: %w", err)
	}
	return nil
}

// outputTable outputs data in table format (human-readable)
// Formats structured data into a readable table view
func (m *manager) outputTable(data interface{}) error {
	// Check if data is a map (status data structure)
	statusData, ok := data.(map[string]interface{})
	if !ok {
		// If not a map, try to format as JSON
		return m.outputJSON(data)
	}

	// Build table output for status data
	fmt.Println()
	fmt.Println("Secrets Database Status")
	fmt.Println("==========================================")
	fmt.Println()

	// Configuration section
	if configData, ok := statusData["configuration"].(map[string]interface{}); ok {
		fmt.Println("Configuration:")
		path := configData["path"].(string)
		exists := configData["exists"].(bool)
		if exists {
			fmt.Printf("  Config file:  %s ✓\n", path)
		} else {
			fmt.Printf("  Config file:  %s ✗ (not found, using defaults)\n", path)
		}
		fmt.Println()
	}

	// Database section
	if dbData, ok := statusData["database"].(map[string]interface{}); ok {
		fmt.Println("Database:")
		path := dbData["path"].(string)
		exists := dbData["exists"].(bool)

		if exists {
			fmt.Printf("  Location:     %s ✓\n", path)
			if sizeHuman, ok := dbData["size_human"].(string); ok {
				fmt.Printf("  Size:         %s\n", sizeHuman)
			}
			if modified, ok := dbData["modified"].(string); ok {
				fmt.Printf("  Modified:     %s\n", modified)
			}
			if accessible, ok := dbData["accessible"].(bool); ok {
				if accessible {
					fmt.Println("  Accessible:   ✓ (password verified)")
					if databaseName, ok := dbData["database_name"].(string); ok {
						fmt.Printf("  Database Name: %s\n", databaseName)
					}
					if entriesCount, ok := dbData["entries_count"].(int); ok {
						fmt.Printf("  Entries Count: %d\n", entriesCount)
					}
				} else {
					errorMsg := ""
					if err, ok := dbData["error"].(string); ok {
						errorMsg = err
					}
					fmt.Printf("  Accessible:   ✗ (%s)\n", errorMsg)
				}
			}
		} else {
			fmt.Printf("  Location:     %s ✗ (not found)\n", path)
			fmt.Println("  Run 'secrets init' to create the database.")
		}
		fmt.Println()
	}

	// Keyfile section
	if keyfileData, ok := statusData["keyfile"].(map[string]interface{}); ok {
		fmt.Println("Keyfile:")
		path := keyfileData["path"].(string)
		exists := keyfileData["exists"].(bool)

		if exists {
			fmt.Printf("  Location:     %s ✓\n", path)
			if modified, ok := keyfileData["modified"].(string); ok {
				fmt.Printf("  Modified:     %s\n", modified)
			}
		} else {
			fmt.Printf("  Location:     %s ✗ (not found)\n", path)
			fmt.Println("  Run 'secrets init' to create the keyfile.")
		}
		fmt.Println()
	}

	return nil
}
