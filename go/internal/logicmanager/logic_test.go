package logicmanager

import (
	"testing"

	"github.com/Yohnah/secrets/internal/bdmanager"
	"github.com/Yohnah/secrets/internal/configmanager"
	"github.com/Yohnah/secrets/internal/inputmanager/cli"
	"github.com/Yohnah/secrets/internal/inputmanager/envvars"
	"github.com/Yohnah/secrets/internal/loggermanager"
	"github.com/Yohnah/secrets/internal/outputmanager"
	"github.com/Yohnah/secrets/internal/validatormanager"
	"github.com/spf13/cobra"
)

func TestNewStandardLogic(t *testing.T) {
	// Create real instances for testing constructor
	logger := loggermanager.NewStderrLogger()
	validator := validatormanager.NewStandardValidator(logger)
	
	// Create cobra command for CLI
	cmd := &cobra.Command{}
	cmd.Flags().String("database-name", "default", "")
	cmd.Flags().String("database-path", "", "")
	cmd.Flags().String("keyfile", "", "")
	cmd.Flags().Bool("non-interactive", false, "")
	cliReader := cli.NewCobraCliReader()
	cliReader.SetCommand(cmd)
	
	envReader := envvars.NewOsEnvVarsReader()
	output := outputmanager.NewStandardOutput(logger)
	bd := bdmanager.NewStandardBD(logger, validator)
	
	// Create config with correct parameter order
	config := configmanager.NewStandardConfig(cliReader, envReader, validator, logger)
	
	logic := NewStandardLogic(config, logger, validator, cliReader, envReader, output, bd)
	
	if logic == nil {
		t.Error("Expected non-nil logic manager")
	}
}
