package output

import (
	"strings"
	"testing"
)

func TestNewTableFormatter(t *testing.T) {
	formatter := NewTableFormatter()

	if formatter == nil {
		t.Fatal("Expected formatter, got nil")
	}

	if formatter.ColumnSeparator != " | " {
		t.Errorf("Expected default separator ' | ', got '%s'", formatter.ColumnSeparator)
	}

	if !formatter.ShowHeaders {
		t.Error("Expected default formatter to show headers")
	}
}

func TestTableFormatter_Format_Nil(t *testing.T) {
	formatter := NewTableFormatter()

	result, err := formatter.Format(nil)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if result != "" {
		t.Errorf("Expected empty string for nil, got '%s'", result)
	}
}

func TestTableFormatter_Format_SimpleStruct(t *testing.T) {
	formatter := NewTableFormatter()

	type TestStruct struct {
		Name  string
		Value int
	}

	data := TestStruct{
		Name:  "test",
		Value: 42,
	}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should contain field names and values
	if !strings.Contains(result, "Name") {
		t.Error("Result should contain 'Name' field")
	}
	if !strings.Contains(result, "Value") {
		t.Error("Result should contain 'Value' field")
	}
	if !strings.Contains(result, "test") {
		t.Error("Result should contain 'test' value")
	}
	if !strings.Contains(result, "42") {
		t.Error("Result should contain '42' value")
	}
}

func TestTableFormatter_Format_StructSlice(t *testing.T) {
	formatter := NewTableFormatter()

	type Item struct {
		ID   int
		Name string
	}

	data := []Item{
		{ID: 1, Name: "first"},
		{ID: 2, Name: "second"},
		{ID: 3, Name: "third"},
	}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should contain headers
	if !strings.Contains(result, "ID") || !strings.Contains(result, "Name") {
		t.Error("Result should contain column headers")
	}

	// Should contain separator line (dashes)
	if !strings.Contains(result, "---") {
		t.Error("Result should contain separator line")
	}

	// Should contain all data values
	lines := strings.Split(result, "\n")
	if len(lines) < 5 { // header + separator + 3 data rows
		t.Errorf("Expected at least 5 lines, got %d", len(lines))
	}

	// Verify data appears in output
	if !strings.Contains(result, "first") || !strings.Contains(result, "second") || !strings.Contains(result, "third") {
		t.Error("Result should contain all data values")
	}
}

func TestTableFormatter_Format_EmptySlice(t *testing.T) {
	formatter := NewTableFormatter()

	data := []string{}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result != "No data" {
		t.Errorf("Expected 'No data', got '%s'", result)
	}
}

func TestTableFormatter_Format_SimpleSlice(t *testing.T) {
	formatter := NewTableFormatter()

	data := []string{"apple", "banana", "cherry"}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should contain all values
	for _, value := range data {
		if !strings.Contains(result, value) {
			t.Errorf("Result should contain '%s'", value)
		}
	}

	// Should have header for simple slice
	if !strings.Contains(result, "Value") {
		t.Error("Result should contain 'Value' header for simple slice")
	}
}

func TestTableFormatter_Format_Map(t *testing.T) {
	formatter := NewTableFormatter()

	data := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
	}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should contain headers
	if !strings.Contains(result, "Key") || !strings.Contains(result, "Value") {
		t.Error("Result should contain 'Key' and 'Value' headers")
	}

	// Should contain data
	if !strings.Contains(result, "key1") || !strings.Contains(result, "value1") {
		t.Error("Result should contain map entries")
	}
}

func TestTableFormatter_Format_MapSlice(t *testing.T) {
	formatter := NewTableFormatter()

	data := []map[string]interface{}{
		{"name": "Alice", "age": 30},
		{"name": "Bob", "age": 25},
	}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should contain data from all maps
	if !strings.Contains(result, "Alice") || !strings.Contains(result, "Bob") {
		t.Error("Result should contain data from all maps")
	}

	// Should have multiple rows
	lines := strings.Split(result, "\n")
	if len(lines) < 4 { // header + separator + 2 data rows
		t.Errorf("Expected at least 4 lines, got %d", len(lines))
	}
}

func TestTableFormatter_Format_WithoutHeaders(t *testing.T) {
	formatter := NewTableFormatter()
	formatter.ShowHeaders = false

	type Item struct {
		Name string
	}

	data := []Item{{Name: "test"}}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should contain data but not header
	if !strings.Contains(result, "test") {
		t.Error("Result should contain data")
	}

	// Should not contain separator line
	if strings.Contains(result, "---") {
		t.Error("Result should not contain separator when ShowHeaders=false")
	}
}

func TestTableFormatter_Format_CustomSeparator(t *testing.T) {
	formatter := NewTableFormatter()
	formatter.ColumnSeparator = " || "

	type Item struct {
		Col1 string
		Col2 string
	}

	data := []Item{{Col1: "a", Col2: "b"}}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should use custom separator
	if !strings.Contains(result, " || ") {
		t.Error("Result should use custom separator ' || '")
	}
}

func TestTableFormatter_Format_UnexportedFields(t *testing.T) {
	formatter := NewTableFormatter()

	type Item struct {
		Public  string
		private string // unexported, should be skipped
	}

	data := []Item{{Public: "visible", private: "hidden"}}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should contain public field
	if !strings.Contains(result, "Public") {
		t.Error("Result should contain Public field")
	}
	if !strings.Contains(result, "visible") {
		t.Error("Result should contain public value")
	}

	// Should not contain private field name (unexported fields skipped)
	if strings.Contains(result, "private") {
		t.Error("Result should not contain unexported field name")
	}
}

func TestTableFormatter_Format_SimpleTypes(t *testing.T) {
	formatter := NewTableFormatter()

	tests := []struct {
		name  string
		input interface{}
	}{
		{"string", "hello"},
		{"int", 42},
		{"bool", true},
		{"float", 3.14},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := formatter.Format(tt.input)
			if err != nil {
				t.Errorf("Error formatting %s: %v", tt.name, err)
			}
			if result == "" {
				t.Errorf("Got empty result for %s", tt.name)
			}
		})
	}
}

func TestTableFormatter_ImplementsOutputFormatter(t *testing.T) {
	// Compile-time check that TableFormatter implements OutputFormatter
	var _ OutputFormatter = (*TableFormatter)(nil)
}

func TestTableFormatter_Format_NoTrailingNewline(t *testing.T) {
	formatter := NewTableFormatter()

	type Item struct {
		Name string
	}

	data := []Item{{Name: "test"}}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should not end with newline
	if strings.HasSuffix(result, "\n") {
		t.Error("Result should not end with trailing newline")
	}
}

func TestTableFormatter_Format_MultipleRowsAlignment(t *testing.T) {
	formatter := NewTableFormatter()

	type Item struct {
		ID   int
		Name string
	}

	data := []Item{
		{ID: 1, Name: "short"},
		{ID: 100, Name: "medium"},
		{ID: 99999, Name: "veryverylongname"},
	}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// All values should be present
	lines := strings.Split(result, "\n")
	if len(lines) < 5 { // header + separator + 3 data rows
		t.Errorf("Expected at least 5 lines, got %d", len(lines))
	}

	// Each line should contain separator
	for i, line := range lines {
		if i == 0 || i == 1 { // header and separator
			continue
		}
		if line != "" && !strings.Contains(line, formatter.ColumnSeparator) {
			t.Errorf("Data line %d should contain separator: %s", i, line)
		}
	}
}

func TestTableFormatter_Format_EmptyStruct(t *testing.T) {
	formatter := NewTableFormatter()

	type Empty struct{}

	data := []Empty{{}, {}}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should handle empty structs gracefully
	if result != "No data" {
		t.Errorf("Expected 'No data' for empty structs, got '%s'", result)
	}
}
