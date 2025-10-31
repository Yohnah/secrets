package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestCobraCliReader_GetStringFlag(t *testing.T) {
	reader := NewCobraCliReader()

	cmd := &cobra.Command{}
	cmd.Flags().String("test-flag", "default-value", "test flag")
	cmd.Flags().Set("test-flag", "custom-value")

	reader.SetCommand(cmd)

	got, err := reader.GetStringFlag("test-flag")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if got != "custom-value" {
		t.Errorf("Expected %q, got %q", "custom-value", got)
	}
}

func TestCobraCliReader_GetBoolFlag(t *testing.T) {
	reader := NewCobraCliReader()

	cmd := &cobra.Command{}
	cmd.Flags().Bool("test-bool", false, "test bool")
	cmd.Flags().Set("test-bool", "true")

	reader.SetCommand(cmd)

	got, err := reader.GetBoolFlag("test-bool")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !got {
		t.Errorf("Expected true, got false")
	}
}

func TestCobraCliReader_NoCommand(t *testing.T) {
	reader := NewCobraCliReader()

	// No command set
	got, err := reader.GetStringFlag("any-flag")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("Expected empty string, got %q", got)
	}
}
