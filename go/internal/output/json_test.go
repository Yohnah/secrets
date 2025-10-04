package output

import (
	"encoding/json"
	"testing"
)

func TestNewJSONFormatter(t *testing.T) {
	formatter := NewJSONFormatter()

	if formatter == nil {
		t.Fatal("Expected formatter, got nil")
	}

	if !formatter.Indent {
		t.Error("Expected default formatter to have Indent=true")
	}
}

func TestNewJSONFormatterCompact(t *testing.T) {
	formatter := NewJSONFormatterCompact()

	if formatter == nil {
		t.Fatal("Expected formatter, got nil")
	}

	if formatter.Indent {
		t.Error("Expected compact formatter to have Indent=false")
	}
}

func TestJSONFormatter_Format_Nil(t *testing.T) {
	formatter := NewJSONFormatter()

	result, err := formatter.Format(nil)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if result != "{}" {
		t.Errorf("Expected '{}', got '%s'", result)
	}
}

func TestJSONFormatter_Format_SimpleStruct(t *testing.T) {
	formatter := NewJSONFormatter()

	type TestStruct struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	data := TestStruct{
		Name:  "test",
		Value: 42,
	}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify it's valid JSON
	var parsed TestStruct
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Errorf("Result is not valid JSON: %v", err)
	}

	// Verify content matches
	if parsed.Name != data.Name || parsed.Value != data.Value {
		t.Errorf("Parsed data doesn't match original. Got %+v, want %+v", parsed, data)
	}
}

func TestJSONFormatter_Format_Map(t *testing.T) {
	formatter := NewJSONFormatter()

	data := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
		"key3": true,
	}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Errorf("Result is not valid JSON: %v", err)
	}

	// Verify keys exist
	if parsed["key1"] != "value1" {
		t.Errorf("Expected key1='value1', got '%v'", parsed["key1"])
	}
}

func TestJSONFormatter_Format_Slice(t *testing.T) {
	formatter := NewJSONFormatter()

	type Item struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}

	data := []Item{
		{ID: 1, Name: "first"},
		{ID: 2, Name: "second"},
	}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify it's valid JSON
	var parsed []Item
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Errorf("Result is not valid JSON: %v", err)
	}

	// Verify length
	if len(parsed) != len(data) {
		t.Errorf("Expected %d items, got %d", len(data), len(parsed))
	}
}

func TestJSONFormatter_Format_CompactVsIndented(t *testing.T) {
	data := map[string]string{
		"key": "value",
	}

	// Test indented
	indentedFormatter := NewJSONFormatter()
	indented, err := indentedFormatter.Format(data)
	if err != nil {
		t.Fatalf("Indented format error: %v", err)
	}

	// Test compact
	compactFormatter := NewJSONFormatterCompact()
	compact, err := compactFormatter.Format(data)
	if err != nil {
		t.Fatalf("Compact format error: %v", err)
	}

	// Indented should be longer (has whitespace)
	if len(indented) <= len(compact) {
		t.Error("Expected indented JSON to be longer than compact")
	}

	// Both should be valid JSON
	var parsedIndented, parsedCompact map[string]string
	if err := json.Unmarshal([]byte(indented), &parsedIndented); err != nil {
		t.Errorf("Indented JSON is invalid: %v", err)
	}
	if err := json.Unmarshal([]byte(compact), &parsedCompact); err != nil {
		t.Errorf("Compact JSON is invalid: %v", err)
	}
}

func TestJSONFormatter_Format_NestedStructure(t *testing.T) {
	formatter := NewJSONFormatter()

	type Address struct {
		Street string `json:"street"`
		City   string `json:"city"`
	}

	type Person struct {
		Name    string  `json:"name"`
		Age     int     `json:"age"`
		Address Address `json:"address"`
	}

	data := Person{
		Name: "John Doe",
		Age:  30,
		Address: Address{
			Street: "123 Main St",
			City:   "Springfield",
		},
	}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify it's valid JSON
	var parsed Person
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Errorf("Result is not valid JSON: %v", err)
	}

	// Verify nested structure
	if parsed.Address.City != data.Address.City {
		t.Errorf("Nested data doesn't match. Got %s, want %s", parsed.Address.City, data.Address.City)
	}
}

func TestJSONFormatter_Format_EmptySlice(t *testing.T) {
	formatter := NewJSONFormatter()

	data := []string{}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should produce valid JSON array
	var parsed []string
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Errorf("Result is not valid JSON: %v", err)
	}

	if len(parsed) != 0 {
		t.Errorf("Expected empty array, got %d items", len(parsed))
	}
}

func TestJSONFormatter_Format_SimpleTypes(t *testing.T) {
	formatter := NewJSONFormatter()

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

func TestJSONFormatter_ImplementsOutputFormatter(t *testing.T) {
	// Compile-time check that JSONFormatter implements OutputFormatter
	var _ OutputFormatter = (*JSONFormatter)(nil)
}

func TestJSONFormatter_Format_WithJSONTags(t *testing.T) {
	formatter := NewJSONFormatter()

	type TaggedStruct struct {
		PublicField  string `json:"public_field"`
		AnotherField int    `json:"another_field"`
		OmitField    string `json:"-"` // Should be omitted
	}

	data := TaggedStruct{
		PublicField:  "visible",
		AnotherField: 100,
		OmitField:    "should_not_appear",
	}

	result, err := formatter.Format(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify JSON tags are respected
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	if parsed["public_field"] != "visible" {
		t.Error("JSON tag 'public_field' not respected")
	}

	if _, exists := parsed["OmitField"]; exists {
		t.Error("Field with json:\"-\" tag should be omitted")
	}
}
