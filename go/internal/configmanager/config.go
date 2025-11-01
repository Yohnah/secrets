package configmanager

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Yohnah/secrets/internal/inputmanager"
	"github.com/Yohnah/secrets/internal/loggermanager"
	"github.com/Yohnah/secrets/internal/validatormanager"
)

type Path string

func (p Path) String() string {
	if p == "" {
		return ""
	}
	return filepath.FromSlash(string(p))
}

type Config interface {
	LoadConfig() error
	HandleInteractiveConfirmationsForInit() error
	ObtainPassword() error
	GetDatabaseName() string
	GetDatabasePath() string
	GetKeyfile() string
	GetPassword() string
	GetConfigPath() string
	GetForceRecreate() bool
	GetNoCreateDatabase() bool
	GetNoKeyfile() bool
	GetIgnoreConfigFile() bool
	GetHomeDir() string
	IsNonInteractive() bool
	ClearPassword()
}

type StandardConfig struct {
	inputManager         inputmanager.InputManager
	validator            validatormanager.Validator
	logger               loggermanager.Logger
	configPath           Path
	databaseName         string
	databasePath         Path
	keyfile              Path
	secretsFile          Path
	verbose              bool
	nonInteractive       bool
	ignoreConfigFile     bool
	forceRecreate        bool
	noCreateDatabase     bool
	noKeyfile            bool
	password             *SecureString
	databasePathExplicit bool
	keyfileExplicit      bool
}

func NewStandardConfig(
	inputManager inputmanager.InputManager,
	validator validatormanager.Validator,
	logger loggermanager.Logger,
) Config {
	return &StandardConfig{
		inputManager: inputManager,
		validator:    validator,
		logger:       logger,
	}
}

func (c *StandardConfig) LoadConfig() error {
	c.logger.Debug("Loading configuration...")
	c.setDefaults()
	c.applyEnvVars()
	if err := c.applyFlags(); err != nil {
		return err
	}
	c.logger.SetVerbose(c.verbose)
	// DO NOT obtain password here - it will be done after interactive confirmations
	if err := c.validate(); err != nil {
		return err
	}
	c.logger.Debug("Configuration loaded successfully")
	return nil
}

func (c *StandardConfig) setDefaults() {
	homeDir, _ := os.UserHomeDir()
	c.configPath = Path(filepath.Join(homeDir, ".secrets", "config.yml"))
	c.databaseName = "default"
	c.databasePath = Path("secrets.kdbx")
	c.keyfile = Path("secrets.key")
	c.secretsFile = Path("./Secrets.yml")
	c.verbose = false
	c.nonInteractive = false
	c.ignoreConfigFile = false
	c.forceRecreate = false
	c.noCreateDatabase = false
	c.noKeyfile = false
	c.databasePathExplicit = false
	c.keyfileExplicit = false
}

func (c *StandardConfig) applyEnvVars() {
	if val, ok := c.inputManager.EnvVars().Get("SECRETS_CONFIG_FILE"); ok && val != "" {
		c.configPath = Path(val)
	}
	if val, ok := c.inputManager.EnvVars().Get("SECRETS_DATABASE"); ok && val != "" {
		c.databasePath = Path(val)
		c.databasePathExplicit = true
	}
	if val, ok := c.inputManager.EnvVars().Get("SECRETS_KEYFILE"); ok && val != "" {
		c.keyfile = Path(val)
		c.keyfileExplicit = true
	}
	if val, ok := c.inputManager.EnvVars().Get("SECRETS_FILE"); ok && val != "" {
		c.secretsFile = Path(val)
	}
}

func (c *StandardConfig) applyFlags() error {
	if val, err := c.inputManager.CLI().GetStringFlag("config"); err == nil && val != "" {
		c.configPath = Path(val)
	}
	if val, err := c.inputManager.CLI().GetStringFlag("database-name"); err == nil && val != "" {
		c.databaseName = val
	}
	if val, err := c.inputManager.CLI().GetStringFlag("database-path"); err == nil && val != "" {
		c.databasePath = Path(val)
		c.databasePathExplicit = true
	}
	if val, err := c.inputManager.CLI().GetStringFlag("keyfile"); err == nil && val != "" {
		c.keyfile = Path(val)
		c.keyfileExplicit = true
	}
	if val, err := c.inputManager.CLI().GetStringFlag("secrets-file"); err == nil && val != "" {
		c.secretsFile = Path(val)
	}
	if val, err := c.inputManager.CLI().GetBoolFlag("verbose"); err == nil {
		c.verbose = val
	}
	if val, err := c.inputManager.CLI().GetBoolFlag("non-interactive"); err == nil {
		c.nonInteractive = val
	}
	if val, err := c.inputManager.CLI().GetBoolFlag("ignore-config-file"); err == nil {
		c.ignoreConfigFile = val
	}
	if val, err := c.inputManager.CLI().GetBoolFlag("force-recreate"); err == nil {
		c.forceRecreate = val
	}
	if val, err := c.inputManager.CLI().GetBoolFlag("no-create-database"); err == nil {
		c.noCreateDatabase = val
	}
	if val, err := c.inputManager.CLI().GetBoolFlag("no-keyfile"); err == nil {
		c.noKeyfile = val
	}
	return nil
}

func (c *StandardConfig) ObtainPassword() error {
	if c.password != nil {
		c.logger.Debug("Password already set")
		return nil
	}
	if password, ok := c.inputManager.EnvVars().Get("SECRETS_PASSWORD"); ok && password != "" {
		c.password = NewSecureString(password)
		c.logger.Debug("Password obtained from environment variable")
		return nil
	}
	if c.nonInteractive {
		err := fmt.Errorf("SECRETS_PASSWORD environment variable required in non-interactive mode")
		c.logger.Error(err.Error())
		return err
	}
	password, err := c.inputManager.Prompts().AskPasswordConfirm("Enter your new password: ")
	if err != nil {
		wrappedErr := fmt.Errorf("failed to obtain password: %w", err)
		c.logger.Error(wrappedErr.Error())
		return wrappedErr
	}
	if password == "" {
		err := fmt.Errorf("password cannot be empty")
		c.logger.Error(err.Error())
		return err
	}
	c.password = NewSecureString(password)
	c.logger.Debug("Password obtained interactively")
	return nil
}

func (c *StandardConfig) HandleInteractiveConfirmationsForInit() error {
	if c.nonInteractive {
		c.logger.Debug("Non-interactive mode: skipping confirmations")
		return nil
	}
	confirm, err := c.inputManager.Prompts().AskConfirmation("Are you sure you want to execute this action?", true)
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}
	if !confirm {
		c.logger.Info("Operation cancelled by user")
		os.Exit(0)
	}
	confirm, err = c.inputManager.Prompts().AskConfirmation("Do you want to create the database in the default location?", true)
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}
	if !confirm {
		c.logger.Info("Custom location requires explicit --database-path flag")
		return fmt.Errorf("please restart with --database-path flag")
	}
	if !c.noKeyfile {
		confirm, err = c.inputManager.Prompts().AskConfirmation("Do you want to protect the database with a keyfile?", true)
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		if !confirm {
			c.noKeyfile = true
			c.logger.Warn("Keyfile protection recommended for security")
		}
	}
	return nil
}

func (c *StandardConfig) validate() error {
	if err := c.validator.ValidateDatabaseName(c.databaseName); err != nil {
		return err
	}
	if err := c.validator.ValidatePath(c.databasePath.String()); err != nil {
		return err
	}
	if err := c.validator.ValidatePath(c.keyfile.String()); err != nil {
		return err
	}
	if err := c.validator.ValidatePath(c.configPath.String()); err != nil {
		return err
	}
	if err := c.validator.ValidatePath(c.secretsFile.String()); err != nil {
		return err
	}
	if c.ignoreConfigFile {
		if !c.databasePathExplicit {
			return fmt.Errorf("--ignore-config-file requires explicit --database-path")
		}
		if !c.noKeyfile && !c.keyfileExplicit {
			return fmt.Errorf("--ignore-config-file requires explicit --keyfile or --no-keyfile")
		}
	}
	return nil
}

func (c *StandardConfig) GetConfigPath() string     { return c.configPath.String() }
func (c *StandardConfig) GetDatabaseName() string   { return c.databaseName }
func (c *StandardConfig) GetDatabasePath() string   { return c.databasePath.String() }
func (c *StandardConfig) GetKeyfile() string        { return c.keyfile.String() }
func (c *StandardConfig) GetSecretsFile() string    { return c.secretsFile.String() }
func (c *StandardConfig) IsVerbose() bool           { return c.verbose }
func (c *StandardConfig) IsNonInteractive() bool    { return c.nonInteractive }
func (c *StandardConfig) IsIgnoreConfigFile() bool  { return c.ignoreConfigFile }
func (c *StandardConfig) GetForceRecreate() bool    { return c.forceRecreate }
func (c *StandardConfig) GetNoCreateDatabase() bool { return c.noCreateDatabase }
func (c *StandardConfig) GetNoKeyfile() bool        { return c.noKeyfile }

func (c *StandardConfig) GetIgnoreConfigFile() bool { return c.ignoreConfigFile }

func (c *StandardConfig) GetHomeDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		c.logger.Fatal(fmt.Sprintf("Failed to get home directory: %v", err))
		os.Exit(1)
	}
	return homeDir
}

func (c *StandardConfig) GetPassword() string {
	if c.password == nil {
		return ""
	}
	return c.password.String()
}

func (c *StandardConfig) SetPassword(password string) {
	if c.password != nil {
		c.password.Clear()
	}
	c.password = NewSecureString(password)
}

func (c *StandardConfig) ClearPassword() {
	if c.password != nil {
		c.password.Clear()
		c.password = nil
	}
}
