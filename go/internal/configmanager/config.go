package configmanager

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Yohnah/secrets/internal/inputmanager/cli"
	"github.com/Yohnah/secrets/internal/inputmanager/envvars"
	"github.com/Yohnah/secrets/internal/loggermanager"
	"github.com/Yohnah/secrets/internal/validatormanager"
)

// Path wrapper normalizes filesystem paths for cross-platform compatibility
type Path string

// String returns the normalized path for the current OS
func (p Path) String() string {
	if p == "" {
		return ""
	}
	return filepath.FromSlash(string(p))
}

// Config interface defines the configuration management contract
type Config interface {
	LoadConfig() error

	// Getters
	GetConfigPath() string
	GetDatabaseName() string
	GetDatabasePath() string
	GetKeyfile() string
	GetSecretsFile() string
	IsVerbose() bool
	IsNonInteractive() bool
	IsIgnoreConfigFile() bool
	GetForceRecreate() bool
	GetNoCreateDatabase() bool
	GetNoKeyfile() bool
	GetPassword() string

	// Setters
	SetPassword(password string)
}

// StandardConfig implements Config with precedence: FLAGS > ENV VARS > DEFAULTS
type StandardConfig struct {
	cliReader cli.CliReader
	envReader envvars.EnvVarsReader
	validator validatormanager.Validator
	logger    loggermanager.Logger

	// Configuration values
	configPath       Path
	databaseName     string
	databasePath     Path
	keyfile          Path
	secretsFile      Path
	verbose          bool
	nonInteractive   bool
	ignoreConfigFile bool
	forceRecreate    bool
	noCreateDatabase bool
	noKeyfile        bool
	password         string

	// Track explicit flag/env settings
	databasePathExplicitlySet bool
	keyfileExplicitlySet      bool
}

// NewStandardConfig creates a new configuration manager
func NewStandardConfig(
	cliReader cli.CliReader,
	envReader envvars.EnvVarsReader,
	validator validatormanager.Validator,
	logger loggermanager.Logger,
) Config {
	return &StandardConfig{
		cliReader: cliReader,
		envReader: envReader,
		validator: validator,
		logger:    logger,
	}
}

// LoadConfig loads and validates configuration with precedence
func (c *StandardConfig) LoadConfig() error {
	c.logger.Debug("Loading configuration...")

	// Step 1: Set defaults
	c.setDefaults()

	// Step 2: Apply environment variables (override defaults)
	c.applyEnvVars()

	// Step 3: Apply CLI flags (override env vars)
	if err := c.applyFlags(); err != nil {
		return err
	}

	// Step 4: Update logger verbose mode
	c.logger.SetVerbose(c.verbose)

	// Step 5: Validate configuration
	if err := c.validate(); err != nil {
		c.logger.Fatal(err.Error())
		return err
	}

	c.logger.Debug("Configuration loaded successfully")
	return nil
}

// setDefaults initializes default values
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
	c.password = ""
	c.databasePathExplicitlySet = false
	c.keyfileExplicitlySet = false
}

// applyEnvVars applies environment variables (override defaults)
func (c *StandardConfig) applyEnvVars() {
	if val, ok := c.envReader.Get("SECRETS_CONFIG_FILE"); ok && val != "" {
		c.configPath = Path(val)
	}
	if val, ok := c.envReader.Get("SECRETS_DATABASE"); ok && val != "" {
		c.databasePath = Path(val)
		c.databasePathExplicitlySet = true
	}
	if val, ok := c.envReader.Get("SECRETS_KEYFILE"); ok && val != "" {
		c.keyfile = Path(val)
		c.keyfileExplicitlySet = true
	}
	if val, ok := c.envReader.Get("SECRETS_FILE"); ok && val != "" {
		c.secretsFile = Path(val)
	}
}

// applyFlags applies CLI flags (override env vars)
func (c *StandardConfig) applyFlags() error {
	if val, err := c.cliReader.GetStringFlag("config"); err == nil && val != "" {
		c.configPath = Path(val)
	}
	if val, err := c.cliReader.GetStringFlag("database-name"); err == nil && val != "" {
		c.databaseName = val
	}
	if val, err := c.cliReader.GetStringFlag("database-path"); err == nil && val != "" {
		c.databasePath = Path(val)
		c.databasePathExplicitlySet = true
	}
	if val, err := c.cliReader.GetStringFlag("keyfile"); err == nil && val != "" {
		c.keyfile = Path(val)
		c.keyfileExplicitlySet = true
	}
	if val, err := c.cliReader.GetStringFlag("secrets-file"); err == nil && val != "" {
		c.secretsFile = Path(val)
	}
	if val, err := c.cliReader.GetBoolFlag("verbose"); err == nil {
		c.verbose = val
	}
	if val, err := c.cliReader.GetBoolFlag("non-interactive"); err == nil {
		c.nonInteractive = val
	}
	if val, err := c.cliReader.GetBoolFlag("ignore-config-file"); err == nil {
		c.ignoreConfigFile = val
	}
	if val, err := c.cliReader.GetBoolFlag("force-recreate"); err == nil {
		c.forceRecreate = val
	}
	if val, err := c.cliReader.GetBoolFlag("no-create-database"); err == nil {
		c.noCreateDatabase = val
	}
	if val, err := c.cliReader.GetBoolFlag("no-keyfile"); err == nil {
		c.noKeyfile = val
	}

	return nil
}

// validate validates all configuration values
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

	// Validate --ignore-config-file requirements
	if err := c.validateIgnoreConfigFile(); err != nil {
		return err
	}

	return nil
}

// validateIgnoreConfigFile validates requirements when --ignore-config-file is set
func (c *StandardConfig) validateIgnoreConfigFile() error {
	if !c.ignoreConfigFile {
		return nil
	}

	// Require explicit database-path
	if !c.databasePathExplicitlySet {
		return fmt.Errorf("--ignore-config-file requires explicit --database-path flag or SECRETS_DATABASE env var")
	}

	// Require explicit keyfile (if not --no-keyfile)
	if !c.noKeyfile && !c.keyfileExplicitlySet {
		return fmt.Errorf("--ignore-config-file requires explicit --keyfile flag or SECRETS_KEYFILE env var (or use --no-keyfile)")
	}

	return nil
}

// Getters

func (c *StandardConfig) GetConfigPath() string {
	return c.configPath.String()
}

func (c *StandardConfig) GetDatabaseName() string {
	return c.databaseName
}

func (c *StandardConfig) GetDatabasePath() string {
	return c.databasePath.String()
}

func (c *StandardConfig) GetKeyfile() string {
	return c.keyfile.String()
}

func (c *StandardConfig) GetSecretsFile() string {
	return c.secretsFile.String()
}

func (c *StandardConfig) IsVerbose() bool {
	return c.verbose
}

func (c *StandardConfig) IsNonInteractive() bool {
	return c.nonInteractive
}

func (c *StandardConfig) IsIgnoreConfigFile() bool {
	return c.ignoreConfigFile
}

func (c *StandardConfig) GetForceRecreate() bool {
	return c.forceRecreate
}

func (c *StandardConfig) GetNoCreateDatabase() bool {
	return c.noCreateDatabase
}

func (c *StandardConfig) GetNoKeyfile() bool {
	return c.noKeyfile
}

func (c *StandardConfig) GetPassword() string {
	return c.password
}

// Setters

func (c *StandardConfig) SetPassword(password string) {
	c.password = password
}
