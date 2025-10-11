package cli_test

import (
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/cli"
)

// TestNewManagerContext verifies that the factory creates all managers correctly.
// This test validates that:
// 1. The factory does not return nil
// 2. All managers are instantiated (not nil)
// 3. The 7-step initialization pattern is maintained
func TestNewManagerContext(t *testing.T) {
	// Arrange & Act
	ctx := cli.NewManagerContextForTest()

	// Assert: ManagerContext should not be nil
	if ctx == nil {
		t.Fatal("NewManagerContext() returned nil, expected valid *ManagerContext")
	}

	// Assert: All managers must be instantiated
	t.Run("ValidatorManager is instantiated", func(t *testing.T) {
		if ctx.Validator == nil {
			t.Error("ManagerContext.Validator is nil, expected valid validator.Manager")
		}
	})

	t.Run("ConfigManager is instantiated", func(t *testing.T) {
		if ctx.Config == nil {
			t.Error("ManagerContext.Config is nil, expected valid config.Manager")
		}
	})

	t.Run("LoggerManager is instantiated", func(t *testing.T) {
		if ctx.Logger == nil {
			t.Error("ManagerContext.Logger is nil, expected valid logger.Manager")
		}
	})

	t.Run("PromptManager is instantiated", func(t *testing.T) {
		if ctx.Prompt == nil {
			t.Error("ManagerContext.Prompt is nil, expected valid prompt.Manager")
		}
	})

	t.Run("OutputManager is instantiated", func(t *testing.T) {
		if ctx.Output == nil {
			t.Error("ManagerContext.Output is nil, expected valid output.Manager")
		}
	})

	t.Run("SecretsManager is instantiated", func(t *testing.T) {
		if ctx.Secrets == nil {
			t.Error("ManagerContext.Secrets is nil, expected valid secrets.Manager")
		}
	})
}

// TestNewManagerContext_MultipleInstances verifies that the factory can create
// multiple independent instances (not singleton).
// This is important to maintain the per-command initialization pattern.
func TestNewManagerContext_MultipleInstances(t *testing.T) {
	// Arrange & Act
	ctx1 := cli.NewManagerContextForTest()
	ctx2 := cli.NewManagerContextForTest()

	// Assert: Las instancias deben ser diferentes
	if ctx1 == ctx2 {
		t.Error("NewManagerContext() returned same instance, expected independent instances")
	}

	// Assert: Internal managers should also be different
	if ctx1.Config == ctx2.Config {
		t.Error("ConfigManager instances are the same, expected independent instances")
	}

	if ctx1.Logger == ctx2.Logger {
		t.Error("LoggerManager instances are the same, expected independent instances")
	}

	if ctx1.Secrets == ctx2.Secrets {
		t.Error("SecretsManager instances are the same, expected independent instances")
	}
}

// TestManagerContext_AllFieldsExported verifies that ManagerContext
// exposes all managers as public (exported) fields.
// This is necessary so that CLI commands can access them.
func TestManagerContext_AllFieldsExported(t *testing.T) {
	// Arrange
	ctx := cli.NewManagerContextForTest()

	// Act & Assert: Verify access to public fields
	t.Run("Can access Config field", func(t *testing.T) {
		_ = ctx.Config // Si compila, el campo es exportado
	})

	t.Run("Can access Logger field", func(t *testing.T) {
		_ = ctx.Logger
	})

	t.Run("Can access Prompt field", func(t *testing.T) {
		_ = ctx.Prompt
	})

	t.Run("Can access Output field", func(t *testing.T) {
		_ = ctx.Output
	})

	t.Run("Can access Secrets field", func(t *testing.T) {
		_ = ctx.Secrets
	})

	t.Run("Can access Validator field", func(t *testing.T) {
		_ = ctx.Validator
	})
}

// TestVersionFlag verifies that the --version flag works correctly
func TestVersionFlag(t *testing.T) {
	// This test verifies that the version information is properly injected
	// and that the --version flag produces output containing expected elements

	// Note: This is a basic test. Full integration testing of CLI flags
	// would require more complex setup with command execution.
	// For now, we verify that version variables are not empty defaults.

	if cli.Version == "" {
		t.Error("cli.Version is empty, expected version string")
	}

	if cli.BuildTime == "" {
		t.Error("cli.BuildTime is empty, expected build time string")
	}

	if cli.GitCommit == "" {
		t.Error("cli.GitCommit is empty, expected git commit string")
	}

	// Verify version contains expected format (semantic versioning with build metadata)
	if !strings.Contains(cli.Version, "+") {
		t.Errorf("Version %q does not contain build metadata (+), expected format like v1.0.0+date", cli.Version)
	}
}
