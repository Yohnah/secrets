package output

import (
	"encoding/json"
	"fmt"
)

// JSONFormatter formats data as JSON output
// Follows Single Responsibility Principle (SRP) - only handles JSON formatting
type JSONFormatter struct {
	// Indent controls whether output should be pretty-printed
	// true = indented with 2 spaces, false = compact
	Indent bool
}

// NewJSONFormatter creates a new JSON formatter with default settings (indented)
// Returns a formatter configured for human-readable JSON output
func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{
		Indent: true, // Default to pretty-printed JSON for readability
	}
}

// NewJSONFormatterCompact creates a new JSON formatter for compact output
// Useful for machine-readable output or when minimizing output size
func NewJSONFormatterCompact() *JSONFormatter {
	return &JSONFormatter{
		Indent: false,
	}
}

// Format converts the provided data to JSON string representation
// Implements OutputFormatter interface
// Returns formatted JSON string or error if data cannot be marshaled
func (f *JSONFormatter) Format(data interface{}) (string, error) {
	if data == nil {
		return "{}", nil
	}

	var bytes []byte
	var err error

	if f.Indent {
		bytes, err = json.MarshalIndent(data, "", "  ")
	} else {
		bytes, err = json.Marshal(data)
	}

	if err != nil {
		return "", fmt.Errorf("failed to format data as JSON: %w", err)
	}

	return string(bytes), nil
}
