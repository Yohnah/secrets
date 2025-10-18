package cli

import (
	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/output"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/Yohnah/secrets/internal/template"
	"github.com/Yohnah/secrets/internal/types"
	"github.com/Yohnah/secrets/internal/validator"
)

// Container provides a centralized dependency injection container
// that manages the creation and lifecycle of all managers.
// This eliminates tight coupling and allows for better testability
// and flexibility in manager instantiation order.
type Container struct {
	// Core dependencies (created first)
	validatorMgr validator.ValidatorManager

	// Configuration layer
	configMgr config.Manager

	// Infrastructure layer
	loggerMgr   logger.Manager
	promptMgr   prompt.Manager
	outputMgr   output.Manager
	keepassMgr  keepass.Manager
	templateMgr template.Manager

	// Business logic layer (depends on infrastructure)
	secretsMgr secrets.Manager
}

// NewContainer creates a new dependency injection container
// with all managers properly initialized and wired together.
func NewContainer(commandFlags *types.CommandFlags) *Container {
	c := &Container{}

	// Initialize in dependency order (from least dependent to most dependent)

	// 1. Core dependencies (no dependencies)
	c.validatorMgr = validator.NewManager()

	// 2. Configuration layer (depends on validator)
	globalFlags := GetGlobalFlags()
	c.configMgr = config.NewManager(globalFlags, commandFlags, c.validatorMgr)

	// 3. Infrastructure layer (depends on config for some settings)
	c.loggerMgr = logger.NewManager(globalFlags.Verbose)
	c.promptMgr = prompt.NewManager()
	c.outputMgr = output.NewManager()
	c.keepassMgr = keepass.NewManager()
	c.templateMgr = template.NewManager()

	// 4. Business logic layer (depends on all infrastructure)
	c.secretsMgr = secrets.NewManager(
		c.configMgr,
		c.loggerMgr,
		c.promptMgr,
		c.keepassMgr,
		c.outputMgr,
		c.templateMgr,
		c.validatorMgr,
	)

	return c
}

// GetValidator returns the validator manager
func (c *Container) GetValidator() validator.ValidatorManager {
	return c.validatorMgr
}

// GetConfig returns the config manager
func (c *Container) GetConfig() config.Manager {
	return c.configMgr
}

// GetLogger returns the logger manager
func (c *Container) GetLogger() logger.Manager {
	return c.loggerMgr
}

// GetPrompt returns the prompt manager
func (c *Container) GetPrompt() prompt.Manager {
	return c.promptMgr
}

// GetOutput returns the output manager
func (c *Container) GetOutput() output.Manager {
	return c.outputMgr
}

// GetKeePass returns the keepass manager
func (c *Container) GetKeePass() keepass.Manager {
	return c.keepassMgr
}

// GetTemplate returns the template manager
func (c *Container) GetTemplate() template.Manager {
	return c.templateMgr
}

// GetSecrets returns the secrets manager (core business logic)
func (c *Container) GetSecrets() secrets.Manager {
	return c.secretsMgr
}

// GetManagerContext returns a ManagerContext for backward compatibility
// This method maintains compatibility with existing code that expects ManagerContext
func (c *Container) GetManagerContext() *ManagerContext {
	return &ManagerContext{
		Config:    c.configMgr,
		Logger:    c.loggerMgr,
		Prompt:    c.promptMgr,
		Output:    c.outputMgr,
		Secrets:   c.secretsMgr,
		Validator: c.validatorMgr,
	}
}
