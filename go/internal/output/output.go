package output

// OutputFormatter defines the interface for all output formatters
// Follows Interface Segregation Principle (ISP) from SOLID
// Each formatter implementation must provide a way to format arbitrary data
type OutputFormatter interface {
	// Format takes arbitrary data and returns a formatted string representation
	// Returns error if the data cannot be formatted
	Format(data interface{}) (string, error)
}

// FormatType represents the type of output format requested
type FormatType string

const (
	// FormatJSON represents JSON output format
	FormatJSON FormatType = "json"

	// FormatTable represents human-readable table output format
	FormatTable FormatType = "table"
)

// NewFormatter creates a new OutputFormatter based on the specified format type
// Follows Factory Pattern for flexible formatter creation
// Returns error if format type is not supported
func NewFormatter(format FormatType) (OutputFormatter, error) {
	switch format {
	case FormatJSON:
		return NewJSONFormatter(), nil
	case FormatTable:
		return NewTableFormatter(), nil
	default:
		return nil, &UnsupportedFormatError{Format: string(format)}
	}
}

// UnsupportedFormatError is returned when an unsupported format type is requested
type UnsupportedFormatError struct {
	Format string
}

func (e *UnsupportedFormatError) Error() string {
	return "unsupported output format: " + e.Format
}
