package secrets

import (
	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/output"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets/initialize"
	"github.com/Yohnah/secrets/internal/secrets/show"
	"github.com/Yohnah/secrets/internal/secrets/snapshots"
	"github.com/Yohnah/secrets/internal/validator"
)

// Manager defines the interface for secrets business logic
// This is the facade that coordinates between subdominios
type Manager interface {
	Init() error
	Status() error
	ShowTemplate() error
	SnapshotsList(profileName string) error
}

type manager struct {
	initService      initialize.Service
	showService      show.Service
	snapshotsService snapshots.Service
}

// NewManager creates a new SecretsManager instance (Facade Pattern)
// The manager delegates operations to specialized services (subdominios)
func NewManager(cfg config.Manager, log logger.Manager, prm prompt.Manager, kp keepass.Manager, out output.Manager, val validator.ValidatorManager) Manager {
	return &manager{
		initService:      initialize.NewService(cfg, log, prm, kp, val),
		showService:      show.NewService(cfg, log, prm, kp, out, val),
		snapshotsService: snapshots.NewService(cfg, log, prm, kp, out, val),
	}
}

// Init delegates to the initialization service
// The service will pull configuration from ConfigMgr
func (m *manager) Init() error {
	return m.initService.Init()
}

// Status delegates to the show service
// The service will pull configuration from ConfigMgr
func (m *manager) Status() error {
	return m.showService.Status()
}

// ShowTemplate delegates to the show service
// The service will pull configuration from ConfigMgr
func (m *manager) ShowTemplate() error {
	return m.showService.Template()
}

// SnapshotsList delegates to the snapshots service
func (m *manager) SnapshotsList(profileName string) error {
	return m.snapshotsService.List(profileName)
}
