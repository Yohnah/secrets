package bdmanager

import (
"testing"
"github.com/stretchr/testify/assert"
)

type mockLogger struct{}
func (m *mockLogger) Debug(msg string) {}
func (m *mockLogger) Info(msg string) {}
func (m *mockLogger) Warn(msg string) {}
func (m *mockLogger) Error(msg string) {}
func (m *mockLogger) Fatal(msg string) {}
func (m *mockLogger) SetVerbose(v bool) {}

type mockValidator struct{}
func (m *mockValidator) ValidateDatabaseName(name string) error { return nil }
func (m *mockValidator) ValidatePath(path string) error { return nil }
func (m *mockValidator) ValidatePassword(password string) error { return nil }

func TestNewStandardBD(t *testing.T) {
logger := &mockLogger{}
validator := &mockValidator{}

bd := NewStandardBD(logger, validator)

assert.NotNil(t, bd)
}
