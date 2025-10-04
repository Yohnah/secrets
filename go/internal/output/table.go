package output

import (
	"fmt"
	"reflect"
	"strings"
)

// TableFormatter formats data as human-readable table output
// Follows Single Responsibility Principle (SRP) - only handles table formatting
type TableFormatter struct {
	// ColumnSeparator is the string used to separate columns (default: " | ")
	ColumnSeparator string

	// ShowHeaders controls whether column headers should be displayed
	ShowHeaders bool
}

// NewTableFormatter creates a new table formatter with default settings
// Returns a formatter configured for human-readable table output
func NewTableFormatter() *TableFormatter {
	return &TableFormatter{
		ColumnSeparator: " | ",
		ShowHeaders:     true,
	}
}

// Format converts the provided data to a human-readable table string
// Implements OutputFormatter interface
// Supports slices of structs, slices of maps, and simple values
// Returns formatted table string or error if data cannot be formatted
func (f *TableFormatter) Format(data interface{}) (string, error) {
	if data == nil {
		return "", nil
	}

	// Handle different data types
	v := reflect.ValueOf(data)

	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		return f.formatSlice(v)
	case reflect.Struct:
		return f.formatStruct(v)
	case reflect.Map:
		return f.formatMap(v)
	default:
		// For simple types, just return string representation
		return fmt.Sprintf("%v", data), nil
	}
}

// formatSlice formats a slice of data as a table
func (f *TableFormatter) formatSlice(v reflect.Value) (string, error) {
	if v.Len() == 0 {
		return "No data", nil
	}

	// Get the first element to determine structure
	first := v.Index(0)

	switch first.Kind() {
	case reflect.Struct:
		return f.formatStructSlice(v)
	case reflect.Map:
		return f.formatMapSlice(v)
	default:
		// For simple slices, format as a single column
		return f.formatSimpleSlice(v)
	}
}

// formatStructSlice formats a slice of structs as a table
func (f *TableFormatter) formatStructSlice(v reflect.Value) (string, error) {
	if v.Len() == 0 {
		return "No data", nil
	}

	first := v.Index(0)
	t := first.Type()

	// Get column names from struct fields
	var columns []string
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		// Skip unexported fields
		if field.PkgPath != "" {
			continue
		}
		columns = append(columns, field.Name)
	}

	if len(columns) == 0 {
		return "No data", nil
	}

	var result strings.Builder

	// Write header
	if f.ShowHeaders {
		result.WriteString(strings.Join(columns, f.ColumnSeparator))
		result.WriteString("\n")

		// Write separator line
		separators := make([]string, len(columns))
		for i, col := range columns {
			separators[i] = strings.Repeat("-", len(col))
		}
		result.WriteString(strings.Join(separators, f.ColumnSeparator))
		result.WriteString("\n")
	}

	// Write rows
	for i := 0; i < v.Len(); i++ {
		row := v.Index(i)
		var values []string

		for j := 0; j < t.NumField(); j++ {
			field := t.Field(j)
			// Skip unexported fields
			if field.PkgPath != "" {
				continue
			}

			fieldValue := row.Field(j)
			values = append(values, fmt.Sprintf("%v", fieldValue.Interface()))
		}

		result.WriteString(strings.Join(values, f.ColumnSeparator))
		result.WriteString("\n")
	}

	return strings.TrimRight(result.String(), "\n"), nil
}

// formatMapSlice formats a slice of maps as a table
func (f *TableFormatter) formatMapSlice(v reflect.Value) (string, error) {
	if v.Len() == 0 {
		return "No data", nil
	}

	// Collect all unique keys across all maps
	keySet := make(map[string]bool)
	for i := 0; i < v.Len(); i++ {
		m := v.Index(i)
		if m.Kind() != reflect.Map {
			continue
		}

		for _, key := range m.MapKeys() {
			keySet[fmt.Sprintf("%v", key.Interface())] = true
		}
	}

	// Convert to sorted slice for consistent column order
	var columns []string
	for key := range keySet {
		columns = append(columns, key)
	}

	if len(columns) == 0 {
		return "No data", nil
	}

	var result strings.Builder

	// Write header
	if f.ShowHeaders {
		result.WriteString(strings.Join(columns, f.ColumnSeparator))
		result.WriteString("\n")

		// Write separator line
		separators := make([]string, len(columns))
		for i, col := range columns {
			separators[i] = strings.Repeat("-", len(col))
		}
		result.WriteString(strings.Join(separators, f.ColumnSeparator))
		result.WriteString("\n")
	}

	// Write rows
	for i := 0; i < v.Len(); i++ {
		m := v.Index(i)
		if m.Kind() != reflect.Map {
			continue
		}

		var values []string
		for _, col := range columns {
			// Find value for this column
			var value string
			for _, key := range m.MapKeys() {
				if fmt.Sprintf("%v", key.Interface()) == col {
					value = fmt.Sprintf("%v", m.MapIndex(key).Interface())
					break
				}
			}
			values = append(values, value)
		}

		result.WriteString(strings.Join(values, f.ColumnSeparator))
		result.WriteString("\n")
	}

	return strings.TrimRight(result.String(), "\n"), nil
}

// formatSimpleSlice formats a slice of simple values as a single column table
func (f *TableFormatter) formatSimpleSlice(v reflect.Value) (string, error) {
	var result strings.Builder

	if f.ShowHeaders {
		result.WriteString("Value\n")
		result.WriteString("-----\n")
	}

	for i := 0; i < v.Len(); i++ {
		result.WriteString(fmt.Sprintf("%v\n", v.Index(i).Interface()))
	}

	return strings.TrimRight(result.String(), "\n"), nil
}

// formatStruct formats a single struct as a two-column table (field: value)
func (f *TableFormatter) formatStruct(v reflect.Value) (string, error) {
	t := v.Type()
	var result strings.Builder

	if f.ShowHeaders {
		result.WriteString("Field" + f.ColumnSeparator + "Value\n")
		result.WriteString("-----" + f.ColumnSeparator + "-----\n")
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		// Skip unexported fields
		if field.PkgPath != "" {
			continue
		}

		fieldValue := v.Field(i)
		result.WriteString(fmt.Sprintf("%s%s%v\n", field.Name, f.ColumnSeparator, fieldValue.Interface()))
	}

	return strings.TrimRight(result.String(), "\n"), nil
}

// formatMap formats a map as a two-column table (key: value)
func (f *TableFormatter) formatMap(v reflect.Value) (string, error) {
	var result strings.Builder

	if f.ShowHeaders {
		result.WriteString("Key" + f.ColumnSeparator + "Value\n")
		result.WriteString("---" + f.ColumnSeparator + "-----\n")
	}

	for _, key := range v.MapKeys() {
		value := v.MapIndex(key)
		result.WriteString(fmt.Sprintf("%v%s%v\n", key.Interface(), f.ColumnSeparator, value.Interface()))
	}

	return strings.TrimRight(result.String(), "\n"), nil
}
