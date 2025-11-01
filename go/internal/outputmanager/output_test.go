package outputmanager

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

func TestNewStandardOutput(t *testing.T) {
logger := &mockLogger{}

output := NewStandardOutput(logger)

assert.NotNil(t, output)
}
