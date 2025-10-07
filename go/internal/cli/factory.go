package cli

import (
	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/output"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/Yohnah/secrets/internal/types"
	"github.com/Yohnah/secrets/internal/validator"
)

// ManagerContext holds all instantiated managers for a command execution.
// This provides a centralized way to create and access all required managers
// following the standard initialization pattern used across all CLI commands.
//
// Architecture: This factory follows the dependency injection pattern where
// all managers are instantiated with their dependencies and exposed through
// interfaces, maintaining SOLID principles (especially Dependency Inversion).
type ManagerContext struct {
	Config    config.Manager
	Logger    logger.Manager
	Prompt    prompt.Manager
	Output    output.Manager
	Secrets   secrets.Manager
	Validator validator.ValidatorManager
}

// NewManagerContext creates all managers with standard setup.
// This follows the proper architectural flow where CliMgr captures ALL user input
// (global flags + command-specific flags) and feeds them to ConfigMgr as raw data.
// ConfigMgr then processes precedence and translates flags to semantic configuration.
//
// Architecture Flow:
//  1. CliMgr captures global flags (from Cobra root command)
//  2. CliMgr captures command-specific flags (from Cobra subcommands)
//  3. CliMgr feeds ALL raw data to ConfigMgr via this factory
//  4. ConfigMgr processes precedence: FLAGS > CONFIG.YML > ENV VARS > DEFAULTS
//  5. ConfigMgr translates flags to semantic config (e.g., -f -> NoInteractive: true)
//  6. SecretsManager pulls processed config when needed
//
// This function ensures consistency across all CLI commands and centralizes
// the dependency injection pattern. All managers communicate through interfaces,
// maintaining SOLID principles.
//
// Example usage:
//
// managers := NewManagerContext(commandFlags)
//
//	if err := managers.Secrets.Init(); err != nil {
//	   managers.Logger.Error(err.Error())
//	   os.Exit(1)
//	}
func NewManagerContext(commandFlags *types.CommandFlags) *ManagerContext {
	// Step 1: Get global flags (captured by Cobra)
	globalFlags := GetGlobalFlags()

	// Step 2: Instantiate ValidatorManager
	validatorMgr := validator.NewManager()

	// Step 3: Instantiate ConfigManager (with ValidatorManager injected)
	// CliMgr feeds ALL raw data (global + command flags) to ConfigMgr
	configMgr := config.NewManager(globalFlags, commandFlags, validatorMgr)

	// Step 4: Instantiate LoggerManager
	loggerMgr := logger.NewManager(globalFlags.Verbose)

	// Step 5: Instantiate PromptManager
	promptMgr := prompt.NewManager()

	// Step 6: Instantiate OutputManager
	outputMgr := output.NewManager()

	// Step 7: Instantiate KeePassManager
	keepassMgr := keepass.NewManager()

	// Step 8: Instantiate SecretsManager (CORE - business logic)
	// SecretsManager receives all dependencies via constructor injection
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepassMgr, outputMgr, validatorMgr)

	return &ManagerContext{
		Config:    configMgr,
		Logger:    loggerMgr,
		Prompt:    promptMgr,
		Output:    outputMgr,
		Secrets:   secretsMgr,
		Validator: validatorMgr,
	}
}

// NewManagerContextForTest is an exported version of NewManagerContext for testing purposes.
// This allows tests in external packages to validate the factory functionality.
func NewManagerContextForTest() *ManagerContext {
	return NewManagerContext(nil)
}
