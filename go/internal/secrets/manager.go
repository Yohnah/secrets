package secrets

import (
	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/output"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets/importer"
	"github.com/Yohnah/secrets/internal/secrets/initialize"
	"github.com/Yohnah/secrets/internal/secrets/profile"
	"github.com/Yohnah/secrets/internal/secrets/show"
	"github.com/Yohnah/secrets/internal/secrets/snapshots"
	"github.com/Yohnah/secrets/internal/template"
	"github.com/Yohnah/secrets/internal/validator"
)

// Manager defines the interface for secrets business logic.
// SecretsManager is the CORE of the application and makes all business decisions.
// It orchestrates all operations by coordinating between specialized services (subdomains).
// This manager decides WHAT to do and delegates HOW to do it to the appropriate services.
// It follows the Facade pattern to provide a unified interface for all secrets operations.
type Manager interface {
	Init() error
	Setup() error
	Status() error
	ShowTemplate() error
	ShowTree(profileName, environmentName, outputFormat string) error
	ShowProfiles(profileFilter string) error
	ShowSyncedData(profileFilter string) error
	SnapshotsList(profileName string) error
	SnapshotsNew(profileName string) error
	SnapshotsRestore(profileName, version string) error
	SnapshotsDelete(profileName, version string) error
	ImportVariables(environmentName string, filePaths []string, decodeBase64 bool) error
	ImportContents(environmentName string, filePaths []string, decodeBase64 bool) error
}

type manager struct {
	initService      initialize.Service
	showService      show.Service
	snapshotsService snapshots.Service
	importService    importer.Service
}

// NewManager creates a new SecretsManager instance (Facade Pattern)
// The manager delegates operations to specialized services (subdominios)
func NewManager(cfg config.Manager, log logger.Manager, prm prompt.Manager, kp keepass.Manager, out output.Manager, tmpl template.Manager, val validator.ValidatorManager) Manager {
	resolver := profile.NewResolver(cfg, log, val)

	return &manager{
		initService:      initialize.NewService(cfg, log, prm, kp, val),
		showService:      show.NewService(cfg, log, prm, kp, out, tmpl, val, resolver),
		snapshotsService: snapshots.NewService(cfg, log, prm, kp, out, val, resolver),
		importService:    importer.NewService(cfg, log, kp, out, prm, val, resolver),
	}
}

// Init delegates to the initialization service
// The service will pull configuration from ConfigMgr
func (m *manager) Init() error {
	return m.initService.Init()
}

// Setup delegates to the initialization service
// Creates infrastructure only (no profile loading)
func (m *manager) Setup() error {
	return m.initService.Setup()
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

// ShowSyncedData delegates to the show service
func (m *manager) ShowSyncedData(profileFilter string) error {
	return m.showService.SyncedData(profileFilter)
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

// ImportVariables delegates to the import service
func (m *manager) ImportVariables(environmentName string, filePaths []string, decodeBase64 bool) error {
	return m.importService.ImportVariables(environmentName, filePaths, decodeBase64)
}

// ImportContents delegates to the import service
func (m *manager) ImportContents(environmentName string, filePaths []string, decodeBase64 bool) error {
	return m.importService.ImportContents(environmentName, filePaths, decodeBase64)
}
