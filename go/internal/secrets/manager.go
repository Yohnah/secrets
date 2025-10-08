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
	ShowTree(profileName, environmentName, outputFormat string) error
	ShowProfiles(profileFilter string) error
	SnapshotsList(profileName string) error
	SnapshotsNew(profileName string) error
	SnapshotsRestore(profileName, version string) error
	SnapshotsDelete(profileName, version string) error
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

// ShowTree delegates to the show service
func (m *manager) ShowTree(profileName, environmentName, outputFormat string) error {
	return m.showService.Tree(profileName, environmentName, outputFormat)
}

// ShowProfiles delegates to the show service
func (m *manager) ShowProfiles(profileFilter string) error {
	return m.showService.Profiles(profileFilter)
}

// SnapshotsList delegates to the snapshots service
func (m *manager) SnapshotsList(profileName string) error {
	return m.snapshotsService.List(profileName)
}

// SnapshotsNew delegates to the snapshots service
func (m *manager) SnapshotsNew(profileName string) error {
	return m.snapshotsService.New(profileName)
}

// SnapshotsRestore delegates to the snapshots service
func (m *manager) SnapshotsRestore(profileName, version string) error {
	return m.snapshotsService.Restore(profileName, version)
}

// SnapshotsDelete delegates to the snapshots service
func (m *manager) SnapshotsDelete(profileName, version string) error {
	return m.snapshotsService.Delete(profileName, version)
}
