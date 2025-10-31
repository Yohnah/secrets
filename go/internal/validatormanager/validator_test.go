package validatormanager

import (
	"testing"

	"github.com/Yohnah/secrets/internal/loggermanager"
)

func TestValidateDatabaseName_Valid(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	validator := NewStandardValidator(logger)

	validNames := []string{
		"default",
		"production",
		"test-db",
		"db_name",
		"DB123",
		"a",
	}

	for _, name := range validNames {
		err := validator.ValidateDatabaseName(name)
		if err != nil {
			t.Errorf("Expected valid name %q, got error: %v", name, err)
		}
	}
}

func TestValidateDatabaseName_Invalid(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	validator := NewStandardValidator(logger)

	invalidNames := []string{
		"",
		"invalid name",
		"name@domain",
		"name.db",
		"this_is_a_very_long_name_that_definitely_exceeds_the_maximum_allowed_length",
	}

	for _, name := range invalidNames {
		err := validator.ValidateDatabaseName(name)
		if err == nil {
			t.Errorf("Expected error for invalid name %q, got nil", name)
		}
	}
}
