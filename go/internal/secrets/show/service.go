package show

import (
	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/output"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/validator"
)

// Service defines the interface for show operations
type Service interface {
	Status(format string) error
	Template(minimal bool) error
}

type service struct {
	config    config.Manager
	logger    logger.Manager
	prompt    prompt.Manager
	keepass   keepass.Manager
	output    output.Manager
	validator validator.ValidatorManager
}

// NewService creates a new show service instance
func NewService(cfg config.Manager, log logger.Manager, prm prompt.Manager, kp keepass.Manager, out output.Manager, val validator.ValidatorManager) Service {
	return &service{
		config:    cfg,
		logger:    log,
		prompt:    prm,
		keepass:   kp,
		output:    out,
		validator: val,
	}
}
