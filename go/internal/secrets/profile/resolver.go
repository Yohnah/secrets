package profile

import (
	"fmt"
	"strings"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/validator"
)

// Resolver defines the contract for resolving profiles from secrets.yml
type Resolver interface {
	// Resolve returns the resolved profile information. If profileName is empty,
	// the resolver will attempt to auto-detect a single profile from secrets.yml.
	Resolve(profileName string) (*ResolvedProfile, error)

	// LoadConfig reads secrets.yml and returns the parsed configuration.
	LoadConfig() (*validator.SecretsConfig, error)
}

// ResolvedProfile represents a successfully resolved profile.
type ResolvedProfile struct {
	Name    string
	Profile *validator.Profile
	Config  *validator.SecretsConfig
}

type resolver struct {
	configManager    config.Manager
	validatorManager validator.ValidatorManager
	loggerManager    logger.Manager
}

// NewResolver creates a new Resolver instance.
func NewResolver(cfg config.Manager, log logger.Manager, val validator.ValidatorManager) Resolver {
	return &resolver{
		configManager:    cfg,
		validatorManager: val,
		loggerManager:    log,
	}
}

// Resolve resolves the profile using the provided name or auto-detects it from secrets.yml.
func (r *resolver) Resolve(profileName string) (*ResolvedProfile, error) {
	config, err := r.loadConfig()
	if err != nil {
		return nil, err
	}

	// If a profile name is provided, validate it exists and return it.
	if profileName != "" {
		for i := range config.Profiles {
			if config.Profiles[i].Metadata.Profile == profileName {
				return &ResolvedProfile{
					Name:    profileName,
					Profile: &config.Profiles[i],
					Config:  config,
				}, nil
			}
		}

		return nil, fmt.Errorf("profile '%s' does not exist in secrets.yml", profileName)
	}

	// No profile explicitly provided: attempt auto-detection.
	profileCount := len(config.Profiles)
	if profileCount == 1 {
		detectedProfile := config.Profiles[0].Metadata.Profile
		if detectedProfile == "" {
			return nil, fmt.Errorf("invalid secrets.yml: profile metadata is empty")
		}

		r.loggerManager.Info(fmt.Sprintf("Auto-detected profile '%s' from secrets.yml", detectedProfile))

		return &ResolvedProfile{
			Name:    detectedProfile,
			Profile: &config.Profiles[0],
			Config:  config,
		}, nil
	}

	if profileCount == 0 {
		return nil, fmt.Errorf("secrets.yml must contain at least one profile")
	}

	// Multiple profiles: require explicit selection via flag.
	profileNames := make([]string, 0, profileCount)
	for _, profile := range config.Profiles {
		if profile.Metadata.Profile != "" {
			profileNames = append(profileNames, profile.Metadata.Profile)
		}
	}

	if len(profileNames) == 0 {
		return nil, fmt.Errorf("multiple profiles found but metadata is missing profile names; please fix secrets.yml")
	}

	return nil, fmt.Errorf(
		"multiple profiles found in secrets.yml (%s). Use -p/--profile-name to select a profile",
		strings.Join(profileNames, ", "),
	)
}

// LoadConfig reads secrets.yml and returns the parsed configuration.
func (r *resolver) LoadConfig() (*validator.SecretsConfig, error) {
	return r.loadConfig()
}

func (r *resolver) loadConfig() (*validator.SecretsConfig, error) {
	secretsFilePath := r.configManager.GetSecretsFilePath()
	if secretsFilePath == "" {
		return nil, fmt.Errorf("secrets.yml file not found. Use --secrets-file flag or set SECRETS_YOHNAH_SECRETS_FILE environment variable")
	}

	config, errs := r.validatorManager.ReadAndValidateSecretsYML(secretsFilePath)
	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid secrets.yml: %v", errs[0])
	}

	return config, nil
}
