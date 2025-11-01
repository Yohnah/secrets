package configmanager

import (
"testing"
"github.com/stretchr/testify/assert"
)

func TestNewSecureString(t *testing.T) {
s := NewSecureString("test-password")
assert.NotNil(t, s)
assert.Equal(t, "test-password", s.String())
}

func TestSecureStringClear(t *testing.T) {
s := NewSecureString("sensitive-data")
assert.Equal(t, "sensitive-data", s.String())

s.Clear()

assert.Empty(t, s.String())
}

func TestSecureStringMultipleClear(t *testing.T) {
s := NewSecureString("test")
s.Clear()
s.Clear() // Should not panic
assert.Empty(t, s.String())
}
