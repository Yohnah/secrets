package validatormanager

import (
	"fmt"
	"regexp"

	"github.com/Yohnah/secrets/internal/loggermanager"
)

// Validator interface defines the validation contract
type Validator interface {
	ValidateDatabaseName(name string) error
	ValidatePath(path string) error
}

// StandardValidator implements Validator with standard validation rules
type StandardValidator struct {
	logger loggermanager.Logger
}

// NewStandardValidator creates a new validator
func NewStandardValidator(logger loggermanager.Logger) Validator {
	return &StandardValidator{
		logger: logger,
	}
}

// ValidateDatabaseName validates database name format
func (v *StandardValidator) ValidateDatabaseName(name string) error {
	if name == "" {
		return fmt.Errorf("database name cannot be empty")
	}

	if len(name) > 64 {
		return fmt.Errorf("database name too long (max 64 characters)")
	}

	match, err := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, name)
	if err != nil {
		return fmt.Errorf("regex error: %w", err)
	}

	if !match {
		return fmt.Errorf("database name must be alphanumeric (allowed: a-z, A-Z, 0-9, _, -)")
	}

	return nil
}

// ValidatePath validates path syntax (basic validation)
func (v *StandardValidator) ValidatePath(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	// Check for invalid characters (null byte)
	for _, r := range path {
		if r == 0 {
			return fmt.Errorf("path contains invalid null character")
		}
	}

	return nil
}
