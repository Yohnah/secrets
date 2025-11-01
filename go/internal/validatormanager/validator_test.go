package validatormanager

import (
"testing"
"github.com/Yohnah/secrets/internal/loggermanager"
)

func TestValidateDatabaseName_Valid(t *testing.T) {
logger := loggermanager.NewStderrLogger()
validator := NewStandardValidator(logger)
names := []string{"default", "production", "test-db"}
for _, name := range names {
if err := validator.ValidateDatabaseName(name); err != nil {
t.Errorf("Expected valid: %v", err)
}
}
}
