package envvars

import (
"os"
"testing"
"github.com/stretchr/testify/assert"
)

func TestNewOsEnvVarsReader(t *testing.T) {
reader := NewOsEnvVarsReader()
assert.NotNil(t, reader)
}

func TestOsEnvVarsReader_Get(t *testing.T) {
reader := NewOsEnvVarsReader()
os.Setenv("TEST_VAR", "test-value")
defer os.Unsetenv("TEST_VAR")

value, ok := reader.Get("TEST_VAR")

assert.True(t, ok)
assert.Equal(t, "test-value", value)
}

func TestOsEnvVarsReader_GetNonExistent(t *testing.T) {
reader := NewOsEnvVarsReader()

value, ok := reader.Get("NON_EXISTENT_VAR_12345")

assert.False(t, ok)
assert.Empty(t, value)
}

func TestOsEnvVarsReader_GetAll(t *testing.T) {
reader := NewOsEnvVarsReader()

envs := reader.GetAll()

assert.NotEmpty(t, envs)
}
