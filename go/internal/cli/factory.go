package cli

import (
	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/output"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets"
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
// This follows the 7-step initialization pattern used across all CLI commands:
//
//  1. Get global flags from Cobra
//  2. Instantiate ValidatorManager
//  3. Instantiate ConfigManager (with ValidatorManager injected)
//  4. Instantiate LoggerManager (with verbose flag)
//  5. Instantiate PromptManager
//  6. Instantiate OutputManager
//  7. Instantiate SecretsManager (CORE - with all dependencies)
//
// This function ensures consistency across all CLI commands and centralizes
// the dependency injection pattern. All managers communicate through interfaces,
// maintaining SOLID principles.
//
// Example usage:
//
// managers := NewManagerContext()
//
//	if err := managers.Secrets.Init(); err != nil {
//	   managers.Logger.Error(err.Error())
//	   os.Exit(1)
//	}
func NewManagerContext() *ManagerContext {
	// Step 1: Get global flags (captured by Cobra)
	globalFlags := GetGlobalFlags()

	// Step 2: Instantiate ValidatorManager
	validatorMgr := validator.NewManager()

	// Step 3: Instantiate ConfigManager (with ValidatorManager injected)
	configMgr := config.NewManager(globalFlags, validatorMgr)

	// Step 4: Instantiate LoggerManager
	loggerMgr := logger.NewManager(globalFlags.Verbose)

	// Step 5: Instantiate PromptManager
	promptMgr := prompt.NewManager()

	// Step 6: Instantiate OutputManager
	outputMgr := output.NewManager()

	// Step 7: Instantiate SecretsManager (CORE - business logic)
	// SecretsManager receives all dependencies via constructor injection
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, outputMgr)

	return &ManagerContext{
		Config:    configMgr,
		Logger:    loggerMgr,
		Prompt:    promptMgr,
		Output:    outputMgr,
		Secrets:   secretsMgr,
		Validator: validatorMgr,
	}
}
