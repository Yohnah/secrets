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
// Removes _display metadata before encoding
func (m *manager) outputJSON(data interface{}) error {
	// Remove _display metadata recursively
	cleanData := m.removeDisplayMetadata(data)

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(cleanData); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}
	return nil
}

// outputYAML outputs data in YAML format
// Removes _display metadata before encoding
func (m *manager) outputYAML(data interface{}) error {
	// Remove _display metadata recursively
	cleanData := m.removeDisplayMetadata(data)

	encoder := yaml.NewEncoder(os.Stdout)
	encoder.SetIndent(2)
	defer encoder.Close()

	if err := encoder.Encode(cleanData); err != nil {
		return fmt.Errorf("failed to encode YAML: %w", err)
	}
	return nil
}

// removeDisplayMetadata recursively removes all _display keys from data
func (m *manager) removeDisplayMetadata(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		// Create new map without _display keys
		cleaned := make(map[string]interface{})
		for key, value := range v {
			if key == "_display" {
				continue // Skip _display metadata
			}
			// Recursively clean nested structures
			cleaned[key] = m.removeDisplayMetadata(value)
		}
		return cleaned
	case []interface{}:
		// Clean each element in slice
		cleaned := make([]interface{}, len(v))
		for i, item := range v {
			cleaned[i] = m.removeDisplayMetadata(item)
		}
		return cleaned
	case []string:
		// Strings slice doesn't need cleaning
		return v
	default:
		// Primitive values return as-is
		return v
	}
}

// outputTable outputs data in table format (human-readable)
// Interprets _display metadata to format output professionally
func (m *manager) outputTable(data interface{}) error {
	// Check if data is a map with display metadata
	statusData, ok := data.(map[string]interface{})
	if !ok {
		// Fallback to JSON if not expected structure
		return m.outputJSON(data)
	}

	// Extract top-level display metadata (never printed)
	displayMeta := m.getDisplayMetadata(statusData)

	// Check for special format handlers
	if format, ok := displayMeta["format"].(string); ok {
		switch format {
		case "snapshots_list":
			return m.renderSnapshotsList(statusData, displayMeta)
		}
	}

	// Print title if present
	if title, ok := displayMeta["title"].(string); ok {
		fmt.Println()
		fmt.Println(title)
		if separator, ok := displayMeta["title_separator"].(string); ok {
			fmt.Println(m.repeatString(separator, len(title)))
		}
		fmt.Println()
	}

	// Process each section (skip _display keys)
	for key, value := range statusData {
		if key == "_display" {
			continue // Skip metadata
		}

		sectionData, ok := value.(map[string]interface{})
		if !ok {
			continue
		}

		m.renderSection(sectionData)
	}

	return nil
}

// getDisplayMetadata extracts _display metadata from a map
func (m *manager) getDisplayMetadata(data map[string]interface{}) map[string]interface{} {
	if meta, ok := data["_display"].(map[string]interface{}); ok {
		return meta
	}
	return make(map[string]interface{})
}

// renderSection renders a section with its display metadata
func (m *manager) renderSection(sectionData map[string]interface{}) {
	displayMeta := m.getDisplayMetadata(sectionData)

	// Print section label
	if label, ok := displayMeta["label"].(string); ok {
		fmt.Printf("%s:\n", label)
	}

	// Get fields configuration
	fieldsConfig, _ := displayMeta["fields"].([]map[string]interface{})

	if len(fieldsConfig) > 0 {
		// Render fields according to configuration
		for _, fieldConfig := range fieldsConfig {
			m.renderField(sectionData, fieldConfig)
		}
	} else {
		// No fields config, print all non-metadata keys
		for key, value := range sectionData {
			if key == "_display" {
				continue
			}
			fmt.Printf("  %s: %v\n", key, value)
		}
	}

	// Render subsections if present
	if subsections, ok := displayMeta["subsections"].([]map[string]interface{}); ok {
		for _, subsectionConfig := range subsections {
			m.renderSubsection(sectionData, subsectionConfig)
		}
	}

	fmt.Println()
}

// renderField renders a single field according to its configuration
func (m *manager) renderField(data map[string]interface{}, fieldConfig map[string]interface{}) {
	key, _ := fieldConfig["key"].(string)
	label, _ := fieldConfig["label"].(string)
	format, _ := fieldConfig["format"].(string)
	condition, _ := fieldConfig["condition"].(string)

	// Check condition
	if condition != "" {
		if condValue, ok := data[condition].(bool); !ok || !condValue {
			return // Skip field if condition not met
		}
	}

	// Get value
	value := data[key]

	// Render according to format
	switch format {
	case "path_with_status":
		m.renderPathWithStatus(label, value, data)
	case "accessible_status":
		m.renderAccessibleStatus(label, data)
	case "compliance_with_file":
		m.renderComplianceWithFile(label, data[key].(map[string]interface{}))
	case "compliance_simple":
		m.renderComplianceSimple(label, data[key].(map[string]interface{}))
	case "simple":
		if value != nil && value != "" {
			fmt.Printf("  %-13s %v\n", label+":", value)
		}
	default:
		if value != nil {
			fmt.Printf("  %-13s %v\n", label+":", value)
		}
	}
}

// renderPathWithStatus renders a path with exists status symbol
func (m *manager) renderPathWithStatus(label string, path interface{}, data map[string]interface{}) {
	exists, _ := data["exists"].(bool)
	symbol := "✗"
	message := ""
	if exists {
		symbol = "✓"
	} else {
		// Check for not_found_message in display metadata
		if displayMeta := m.getDisplayMetadata(data); displayMeta != nil {
			if msg, ok := displayMeta["not_found_message"].(string); ok {
				message = msg
			}
		}
	}

	fmt.Printf("  %-13s %v %s", label+":", path, symbol)
	if !exists && message != "" {
		fmt.Printf(" (not found)")
	}
	fmt.Println()

	// Print not_found_message on next line if exists
	if !exists && message != "" {
		fmt.Printf("  %s\n", message)
	}
}

// renderAccessibleStatus renders database accessible status
func (m *manager) renderAccessibleStatus(label string, data map[string]interface{}) {
	accessible, _ := data["accessible"].(bool)
	message, _ := data["accessible_message"].(string)

	symbol := "✗"
	if accessible {
		symbol = "✓"
	}

	fmt.Printf("  %-13s %s", label+":", symbol)
	if message != "" {
		fmt.Printf(" (%s)", message)
	}
	fmt.Println()
}

// renderComplianceWithFile renders compliance status with filename
func (m *manager) renderComplianceWithFile(label string, fieldData map[string]interface{}) {
	checked, _ := fieldData["checked"].(bool)
	if !checked {
		status, _ := fieldData["status"].(string)
		fmt.Printf("  %-13s %s\n", label+":", status)
		return
	}

	file, _ := fieldData["file"].(string)
	status, _ := fieldData["status"].(string)
	symbol, _ := fieldData["symbol"].(string)

	fmt.Printf("  %-13s %s - %s %s\n", label+":", file, symbol, status)
}

// renderComplianceSimple renders simple compliance status
func (m *manager) renderComplianceSimple(label string, fieldData map[string]interface{}) {
	checked, _ := fieldData["checked"].(bool)
	if !checked {
		status, _ := fieldData["status"].(string)
		fmt.Printf("  %-13s %s\n", label+":", status)
		return
	}

	status, _ := fieldData["status"].(string)
	symbol, _ := fieldData["symbol"].(string)

	fmt.Printf("  %-13s %s %s\n", label+":", symbol, status)
}

// renderSubsection renders a subsection (like reports list)
func (m *manager) renderSubsection(data map[string]interface{}, subsectionConfig map[string]interface{}) {
	key, _ := subsectionConfig["key"].(string)
	title, _ := subsectionConfig["title"].(string)
	separator, _ := subsectionConfig["title_separator"].(string)
	format, _ := subsectionConfig["format"].(string)

	// Get subsection data
	subsectionData := data[key]
	if subsectionData == nil {
		return // Skip if no data
	}

	// Print subsection title
	fmt.Println()
	if title != "" {
		fmt.Printf("  %s\n", title)
		if separator != "" {
			fmt.Printf("  %s\n", m.repeatString(separator, len(title)))
		}
	}

	// Render according to format
	switch format {
	case "numbered_list":
		if items, ok := subsectionData.([]string); ok {
			for i, item := range items {
				fmt.Printf("  %d. %s\n", i+1, item)
			}
		}
	default:
		fmt.Printf("  %v\n", subsectionData)
	}
}

// repeatString repeats a string n times
func (m *manager) repeatString(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}

// renderSnapshotsList renders snapshots in a compact list format with visual indicators
// Format (Propuesta 3: Compacta con Indicadores Visuales):
//
// Snapshots
// =========
//
// Profile: name (X snapshot/s)
//
//	✓ HEAD      5h (mutable)
//	  v1        2d
//	  v2        5d
func (m *manager) renderSnapshotsList(data map[string]interface{}, displayMeta map[string]interface{}) error {
	// Print title if present
	if title, ok := displayMeta["title"].(string); ok {
		fmt.Println()
		fmt.Println(title)
		fmt.Println(m.repeatString("=", len(title)))
		fmt.Println()
	}

	// Get profiles data
	profilesRaw := data["profiles"]
	if profilesRaw == nil {
		fmt.Println("No snapshots found")
		return nil
	}

	// Try to convert to []interface{}
	profilesData, ok := profilesRaw.([]interface{})
	if !ok {
		// Try to convert to []map[string]interface{}
		if profilesSlice, ok2 := profilesRaw.([]map[string]interface{}); ok2 {
			// Convert to []interface{}
			profilesData = make([]interface{}, len(profilesSlice))
			for i, p := range profilesSlice {
				profilesData[i] = p
			}
		} else {
			// Unknown type, fallback to JSON
			return m.outputJSON(data)
		}
	}

	if len(profilesData) == 0 {
		fmt.Println("No snapshots found")
		return nil
	}

	// Render each profile
	for _, profileItem := range profilesData {
		profileMap, ok := profileItem.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract profile info
		profileName, _ := profileMap["name"].(string)
		total := 0
		if t, ok := profileMap["total"].(int); ok {
			total = t
		}

		// Profile header
		pluralSuffix := ""
		if total != 1 {
			pluralSuffix = "s"
		}
		fmt.Printf("Profile: %s (%d snapshot%s)\n", profileName, total, pluralSuffix)

		// Get snapshots array
		snapshotsRaw := profileMap["snapshots"]
		if snapshotsRaw == nil {
			fmt.Println("  No snapshots")
			fmt.Println()
			continue
		}

		// Try to convert to []interface{}
		snapshotsData, ok := snapshotsRaw.([]interface{})
		if !ok {
			// Try to convert to []map[string]interface{}
			if snapshotsSlice, ok2 := snapshotsRaw.([]map[string]interface{}); ok2 {
				// Convert to []interface{}
				snapshotsData = make([]interface{}, len(snapshotsSlice))
				for i, s := range snapshotsSlice {
					snapshotsData[i] = s
				}
			} else {
				// Unknown type, skip
				fmt.Println("  No snapshots")
				fmt.Println()
				continue
			}
		}

		if len(snapshotsData) == 0 {
			fmt.Println("  No snapshots")
			fmt.Println()
			continue
		}

		// Render each snapshot
		for _, snapshotItem := range snapshotsData {
			snapshotMap, ok := snapshotItem.(map[string]interface{})
			if !ok {
				continue
			}

			version, _ := snapshotMap["version"].(string)
			age, _ := snapshotMap["age"].(string)
			isActive := false
			if ia, ok := snapshotMap["is_active"].(bool); ok {
				isActive = ia
			}
			isMutable := false
			if im, ok := snapshotMap["is_mutable"].(bool); ok {
				isMutable = im
			}

			// Indicator (✓ for active/HEAD, space otherwise)
			indicator := " "
			if isActive {
				indicator = "✓"
			}

			// Mutable marker
			mutableStr := ""
			if isMutable {
				mutableStr = " (mutable)"
			}

			// Print snapshot line
			fmt.Printf("  %s %-8s  %s%s\n", indicator, version, age, mutableStr)
		}

		fmt.Println()
	}

	return nil
}
