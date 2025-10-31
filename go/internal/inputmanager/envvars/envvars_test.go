package envvars

import (
	"os"
	"testing"
)

func TestOsEnvVarsReader_Get(t *testing.T) {
	reader := NewOsEnvVarsReader()

	// Set test env var
	key := "TEST_SECRET_VAR"
	value := "test_value"
	os.Setenv(key, value)
	defer os.Unsetenv(key)

	got, ok := reader.Get(key)
	if !ok {
		t.Errorf("Expected env var %q to exist", key)
	}
	if got != value {
		t.Errorf("Expected %q, got %q", value, got)
	}
}

func TestOsEnvVarsReader_GetNonExistent(t *testing.T) {
	reader := NewOsEnvVarsReader()

	key := "NON_EXISTENT_VAR_12345"
	_, ok := reader.Get(key)
	if ok {
		t.Errorf("Expected env var %q to not exist", key)
	}
}
