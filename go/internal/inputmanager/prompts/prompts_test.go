package prompts

import (
"testing"
"github.com/stretchr/testify/assert"
)

func TestNewStandardPrompts(t *testing.T) {
prompts := NewStandardPrompts()
assert.NotNil(t, prompts)
}
