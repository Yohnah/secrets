package readfile

import (
"os"
"testing"
"github.com/stretchr/testify/assert"
)

func TestNewStandardFileReader(t *testing.T) {
reader := NewStandardFileReader()
assert.NotNil(t, reader)
}

func TestStandardFileReader_ReadRaw(t *testing.T) {
reader := NewStandardFileReader()

// Create temp file
tmpFile, err := os.CreateTemp("", "test-*.txt")
assert.NoError(t, err)
defer os.Remove(tmpFile.Name())

content := []byte("test content")
_, err = tmpFile.Write(content)
assert.NoError(t, err)
tmpFile.Close()

// Read file
data, err := reader.ReadRaw(tmpFile.Name())

assert.NoError(t, err)
assert.Equal(t, content, data)
}

func TestStandardFileReader_ReadYAML(t *testing.T) {
reader := NewStandardFileReader()

// Create temp YAML file
tmpFile, err := os.CreateTemp("", "test-*.yml")
assert.NoError(t, err)
defer os.Remove(tmpFile.Name())

yamlContent := []byte("key: value\nnumber: 123")
_, err = tmpFile.Write(yamlContent)
assert.NoError(t, err)
tmpFile.Close()

// Read YAML
data, err := reader.ReadYAML(tmpFile.Name())

assert.NoError(t, err)
assert.Equal(t, "value", data["key"])
assert.Equal(t, 123, data["number"])
}
