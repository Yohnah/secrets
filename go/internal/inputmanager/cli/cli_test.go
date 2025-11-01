package cli

import (
"testing"
"github.com/spf13/cobra"
"github.com/stretchr/testify/assert"
)

func TestNewCobraCliReader(t *testing.T) {
reader := NewCobraCliReader()
assert.NotNil(t, reader)
}

func TestCobraCliReader_SetCommand(t *testing.T) {
reader := NewCobraCliReader()
cmd := &cobra.Command{Use: "test"}

reader.SetCommand(cmd)

assert.Equal(t, "test", reader.GetCommand())
}

func TestCobraCliReader_GetStringFlag(t *testing.T) {
reader := NewCobraCliReader()
cmd := &cobra.Command{Use: "test"}
cmd.Flags().String("name", "default", "test flag")
reader.SetCommand(cmd)

value, err := reader.GetStringFlag("name")

assert.NoError(t, err)
assert.Equal(t, "default", value)
}

func TestCobraCliReader_GetBoolFlag(t *testing.T) {
reader := NewCobraCliReader()
cmd := &cobra.Command{Use: "test"}
cmd.Flags().Bool("verbose", false, "test flag")
reader.SetCommand(cmd)

value, err := reader.GetBoolFlag("verbose")

assert.NoError(t, err)
assert.False(t, value)
}
