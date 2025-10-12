package show

import (
	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/output"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets/profile"
	"github.com/Yohnah/secrets/internal/validator"
)

// Service defines the interface for show operations
type Service interface {
	Status() error
	Template() error
	Tree(profileName, environmentName, outputFormat string) error
	Profiles(profileFilter string) error
	SyncedData(profileFilter string) error
}

type service struct {
	config          config.Manager
	logger          logger.Manager
	prompt          prompt.Manager
	keepass         keepass.Manager
	output          output.Manager
	validator       validator.ValidatorManager
	profileResolver profile.Resolver
}

// NewService creates a new show service instance
func NewService(cfg config.Manager, log logger.Manager, prm prompt.Manager, kp keepass.Manager, out output.Manager, val validator.ValidatorManager, resolver profile.Resolver) Service {
	return &service{
		config:          cfg,
		logger:          log,
		prompt:          prm,
		keepass:         kp,
		output:          out,
		validator:       val,
		profileResolver: resolver,
	}
}
