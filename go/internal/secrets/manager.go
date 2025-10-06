package secrets

import (
	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/output"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets/initialize"
	"github.com/Yohnah/secrets/internal/secrets/show"
	"github.com/Yohnah/secrets/internal/validator"
)

// Manager defines the interface for secrets business logic
// This is the facade that coordinates between subdominios
type Manager interface {
	Init(opts initialize.Options) error
	Status(format string) error
	ShowTemplate(minimal bool) error
}

type manager struct {
	initService initialize.Service
	showService show.Service
}

// NewManager creates a new SecretsManager instance (Facade Pattern)
// The manager delegates operations to specialized services (subdominios)
func NewManager(cfg config.Manager, log logger.Manager, prm prompt.Manager, kp keepass.Manager, out output.Manager, val validator.ValidatorManager) Manager {
	return &manager{
		initService: initialize.NewService(cfg, log, prm, kp, val),
		showService: show.NewService(cfg, log, prm, kp, out, val),
	}
}

// Init delegates to the initialization service
func (m *manager) Init(opts initialize.Options) error {
	return m.initService.Init(opts)
}

// Status delegates to the show service
func (m *manager) Status(format string) error {
	return m.showService.Status(format)
}

// ShowTemplate delegates to the show service
func (m *manager) ShowTemplate(minimal bool) error {
	return m.showService.Template(minimal)
}
