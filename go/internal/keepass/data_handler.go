package keepass

import (
	"errors"

	"github.com/Yohnah/secrets/internal/secrets"
)

// DataHandler handles data operations (SRP - Single Responsibility)
type DataHandler struct{}

// NewDataHandler creates a new DataHandler
func NewDataHandler() secrets.DataHandler {
	return &DataHandler{}
}

// FindEntry finds an entry (simplified for SOLID demo)
func (d *DataHandler) FindEntry(db interface{}, entryPath string) (interface{}, error) {
	return map[string]interface{}{"path": entryPath}, nil
}

// CreateEntry creates a new entry (simplified for SOLID demo)  
func (d *DataHandler) CreateEntry(db interface{}, entryPath string) (interface{}, error) {
	return map[string]interface{}{"path": entryPath, "created": true}, nil
}

// SaveDatabase saves the database (simplified for SOLID demo)
func (d *DataHandler) SaveDatabase(db interface{}, path string) error {
	if path == "" {
		return errors.New("path cannot be empty")
	}
	return nil
}