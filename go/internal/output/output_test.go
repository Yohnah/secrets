package output

import (
	"strings"
	"testing"
)

func TestNewFormatter(t *testing.T) {
	tests := []struct {
		name        string
		format      FormatType
		expectError bool
	}{
		{
			name:        "JSON formatter",
			format:      FormatJSON,
			expectError: false,
		},
		{
			name:        "Table formatter",
			format:      FormatTable,
			expectError: false,
		},
		{
			name:        "Unsupported format",
			format:      FormatType("xml"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter, err := NewFormatter(tt.format)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if formatter != nil {
					t.Error("Expected nil formatter on error")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if formatter == nil {
					t.Error("Expected formatter but got nil")
				}
			}
		})
	}
}

func TestUnsupportedFormatError(t *testing.T) {
	err := &UnsupportedFormatError{Format: "xml"}
	expected := "unsupported output format: xml"

	if err.Error() != expected {
		t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestFormatTypes(t *testing.T) {
	tests := []struct {
		name     string
		format   FormatType
		expected string
	}{
		{
			name:     "JSON format constant",
			format:   FormatJSON,
			expected: "json",
		},
		{
			name:     "Table format constant",
			format:   FormatTable,
			expected: "table",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.format) != tt.expected {
				t.Errorf("Expected format '%s', got '%s'", tt.expected, string(tt.format))
			}
		})
	}
}

func TestFormatterInterface(t *testing.T) {
	// Test that our formatters implement the OutputFormatter interface
	var _ OutputFormatter = (*JSONFormatter)(nil)
	var _ OutputFormatter = (*TableFormatter)(nil)
}

func TestNewFormatterReturnsCorrectType(t *testing.T) {
	jsonFormatter, err := NewFormatter(FormatJSON)
	if err != nil {
		t.Fatalf("Unexpected error creating JSON formatter: %v", err)
	}
	if _, ok := jsonFormatter.(*JSONFormatter); !ok {
		t.Error("Expected JSONFormatter type")
	}

	tableFormatter, err := NewFormatter(FormatTable)
	if err != nil {
		t.Fatalf("Unexpected error creating Table formatter: %v", err)
	}
	if _, ok := tableFormatter.(*TableFormatter); !ok {
		t.Error("Expected TableFormatter type")
	}
}

func TestUnsupportedFormatErrorType(t *testing.T) {
	_, err := NewFormatter(FormatType("yaml"))

	if err == nil {
		t.Fatal("Expected error for unsupported format")
	}

	unsupportedErr, ok := err.(*UnsupportedFormatError)
	if !ok {
		t.Errorf("Expected *UnsupportedFormatError, got %T", err)
	}

	if unsupportedErr.Format != "yaml" {
		t.Errorf("Expected format 'yaml', got '%s'", unsupportedErr.Format)
	}
}

func TestFormatterFactoryPattern(t *testing.T) {
	// Test that factory pattern allows easy extension
	formats := []FormatType{FormatJSON, FormatTable}

	for _, format := range formats {
		formatter, err := NewFormatter(format)
		if err != nil {
			t.Errorf("Failed to create formatter for %s: %v", format, err)
			continue
		}

		// Test that formatter can format simple data
		result, err := formatter.Format("test")
		if err != nil {
			t.Errorf("Formatter %s failed to format simple string: %v", format, err)
		}
		if result == "" {
			t.Errorf("Formatter %s returned empty string", format)
		}
	}
}

func TestFormatTypeStringConversion(t *testing.T) {
	// Verify that FormatType can be converted to string and used in maps/switches
	formatMap := map[string]FormatType{
		"json":  FormatJSON,
		"table": FormatTable,
	}

	if formatMap["json"] != FormatJSON {
		t.Error("JSON format not correctly stored in map")
	}
	if formatMap["table"] != FormatTable {
		t.Error("Table format not correctly stored in map")
	}

	// Test reverse lookup
	for key, value := range formatMap {
		if string(value) != key {
			t.Errorf("Format value %s does not match key %s", string(value), key)
		}
	}
}

func TestOutputFormatterNilData(t *testing.T) {
	formatters := []struct {
		name      string
		formatter OutputFormatter
	}{
		{"JSON", NewJSONFormatter()},
		{"Table", NewTableFormatter()},
	}

	for _, tt := range formatters {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.formatter.Format(nil)
			if err != nil {
				t.Errorf("Formatter %s failed on nil data: %v", tt.name, err)
			}
			// Both formatters should handle nil gracefully
			if result == "" && tt.name == "JSON" {
				t.Errorf("JSON formatter returned empty string for nil (expected '{}')")
			}
		})
	}
}

func TestErrorMessageFormat(t *testing.T) {
	_, err := NewFormatter(FormatType("invalid-format"))

	if err == nil {
		t.Fatal("Expected error for invalid format")
	}

	errorMsg := err.Error()
	if !strings.Contains(errorMsg, "unsupported output format") {
		t.Errorf("Error message should contain 'unsupported output format', got: %s", errorMsg)
	}
	if !strings.Contains(errorMsg, "invalid-format") {
		t.Errorf("Error message should contain the format name, got: %s", errorMsg)
	}
}
