package cli_test

import (
	"testing"

	"github.com/Yohnah/secrets/internal/cli"
	"github.com/Yohnah/secrets/internal/types"
)

func TestNewContainer(t *testing.T) {
	// Test that container can be created without panicking
	container := cli.NewContainer(nil)
	if container == nil {
		t.Fatal("Container should not be nil")
	}
}

func TestContainerDependencyInjection(t *testing.T) {
	container := cli.NewContainer(nil)

	// Test that all managers are properly injected and not nil
	if container.GetValidator() == nil {
		t.Error("ValidatorManager should not be nil")
	}

	if container.GetConfig() == nil {
		t.Error("ConfigManager should not be nil")
	}

	if container.GetLogger() == nil {
		t.Error("LoggerManager should not be nil")
	}

	if container.GetPrompt() == nil {
		t.Error("PromptManager should not be nil")
	}

	if container.GetOutput() == nil {
		t.Error("OutputManager should not be nil")
	}

	if container.GetKeePass() == nil {
		t.Error("KeePassManager should not be nil")
	}

	if container.GetTemplate() == nil {
		t.Error("TemplateManager should not be nil")
	}

	if container.GetSecrets() == nil {
		t.Error("SecretsManager should not be nil")
	}
}

func TestContainerManagerContext(t *testing.T) {
	container := cli.NewContainer(&types.CommandFlags{})

	// Test that GetManagerContext returns a valid ManagerContext
	ctx := container.GetManagerContext()
	if ctx == nil {
		t.Fatal("ManagerContext should not be nil")
	}

	// Test that all fields in ManagerContext are properly set
	if ctx.Config == nil {
		t.Error("ManagerContext.Config should not be nil")
	}

	if ctx.Logger == nil {
		t.Error("ManagerContext.Logger should not be nil")
	}

	if ctx.Prompt == nil {
		t.Error("ManagerContext.Prompt should not be nil")
	}

	if ctx.Output == nil {
		t.Error("ManagerContext.Output should not be nil")
	}

	if ctx.Secrets == nil {
		t.Error("ManagerContext.Secrets should not be nil")
	}

	if ctx.Validator == nil {
		t.Error("ManagerContext.Validator should not be nil")
	}
}

func TestContainerWithCommandFlags(t *testing.T) {
	flags := &types.CommandFlags{
		ForceRecreate: true,
		DatabaseName:  "test-db",
	}

	container := cli.NewContainer(flags)

	// Test that container handles command flags properly
	if container.GetConfig() == nil {
		t.Error("ConfigManager should handle command flags")
	}
}
