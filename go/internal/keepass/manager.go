package keepass

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Yohnah/secrets/internal/secrets/common"
	"github.com/tobischo/gokeepasslib/v3"
)

// SessionManager defines operations for session management
type SessionManager interface {
	Open(dbPath, keyfilePath, password string) error
	SaveAndClose() error
	CloseWithoutSave() error
	IsOpen() bool
	GetDatabase() *gokeepasslib.Database
}

// DatabaseManager defines operations for database infrastructure creation
type DatabaseManager interface {
	CreateDatabase(dbPath, keyfilePath, password, rootGroupName string) error
	GenerateKeyfile(keyfilePath string) error
}

// ProfileManager defines operations for profile, group, entry, and field management
type ProfileManager interface {
	// Profile operations
	CreateProfile(profileName string) error
	ProfileExists(profileName string) (bool, error)

	// Group operations
	CreateGroup(profileName, parentGroupName, groupName string) (bool, error)
	GroupExists(profileName, parentGroupName, groupName string) (bool, error)
	GetRootGroups() ([]string, error)
	GetGroupsByParent(parentPath string) ([]string, error)

	// Entry operations
	CreateEntry(profileName, envName, entryPath string) error
	EntryExists(profileName, envName, entryPath string) (bool, error)
	GetEntriesByEnvironment(profileName, envName string) ([]string, error)
	GetEntriesByGroup(groupPath string) ([]string, error)

	// Field operations
	GetFieldsByEntry(entryPath string) ([]string, error)
	GetFieldsByEnvironmentEntry(profileName, envName, entryPath string) ([]string, error)
	GetAllFieldsByEnvironmentEntry(profileName, envName, entryPath string) ([]string, error)
	IsStandardField(fieldName string) bool
	SetStandardField(profileName, envName, entryPath, fieldName, value string) error
	SetCustomField(profileName, envName, entryPath, fieldName, value string) error
	CreateAttachment(profileName, envName, entryPath, attachmentName string, data []byte) error
	DeleteAttachment(profileName, envName, entryPath, attachmentName string) error
	FieldExists(profileName, envName, entryPath, fieldName string) (bool, error)
	GetFieldValue(profileName, envName, entryPath, fieldName string) (string, error)
	GetAttachmentContent(profileName, envName, entryPath, attachmentName string) ([]byte, error)
}

// SnapshotManager defines operations for snapshot (tree group) management
type SnapshotManager interface {
	ListProfileTreeGroups(profileName string) ([]string, error)
	GetTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName string) (*common.SecureValue, error)
	CloneTreeGroup(profileName, sourceTreeGroup, targetTreeGroup string) error
	SetTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName, value string) error
	TreeGroupExists(profileName, treeGroup string) (bool, error)
	RenameTreeGroup(profileName, oldName, newName string) error
	DeleteTreeGroup(profileName, treeGroup string) error
}

// Manager is the main interface that composes all specialized managers
// This maintains backward compatibility while allowing specialized access
type Manager interface {
	SessionManager
	DatabaseManager
	ProfileManager
	SnapshotManager
}

// manager implements the Manager interface
type manager struct {
	db          *gokeepasslib.Database
	dbPath      string
	keyfilePath string
	password    []byte // Changed from string to []byte for secure cleanup

	fs FileSystemPort

	// pathCache stores split paths to avoid repeated string.Split calls
	// Key: path string, Value: []string components
	// Cache is cleared on any database modification operation
	pathCache map[string][]string

	sessionOps  *sessionManager
	databaseOps *databaseManager
	profileOps  *profileManager
	snapshotOps *snapshotManager
}

// NewManager creates a new instance of the KeePass Manager
func NewManager() Manager {
	return NewManagerWithFileSystem(osFileSystemAdapter{})
}

// NewManagerWithFileSystem allows injecting a custom filesystem adapter (useful for tests).
func NewManagerWithFileSystem(fs FileSystemPort) Manager {
	mgr := &manager{
		fs:        fs,
		pathCache: make(map[string][]string),
	}
	mgr.sessionOps = &sessionManager{parent: mgr}
	mgr.databaseOps = &databaseManager{parent: mgr}
	mgr.profileOps = &profileManager{parent: mgr}
	mgr.snapshotOps = &snapshotManager{parent: mgr}
	return mgr
}

// Session operations delegate to session manager
func (m *manager) Open(dbPath, keyfilePath, password string) error {
	return m.sessionOps.Open(dbPath, keyfilePath, password)
}

func (m *manager) saveAndClose() error {
	return m.sessionOps.SaveAndClose()
}

func (m *manager) closeWithoutSave() error {
	return m.sessionOps.CloseWithoutSave()
}

func (m *manager) isOpen() bool {
	return m.sessionOps.IsOpen()
}

func (m *manager) GetDatabase() *gokeepasslib.Database {
	return m.sessionOps.GetDatabase()
}

// Database operations delegate to database manager
func (m *manager) CreateDatabase(dbPath, keyfilePath, password, rootGroupName string) error {
	return m.databaseOps.CreateDatabase(dbPath, keyfilePath, password, rootGroupName)
}

func (m *manager) generateKeyfile(keyfilePath string) error {
	return m.databaseOps.GenerateKeyfile(keyfilePath)
}

// Profile operations delegate to profile manager
func (m *manager) createProfile(profileName string) error {
	return m.profileOps.CreateProfile(profileName)
}

func (m *manager) profileExists(profileName string) (bool, error) {
	return m.profileOps.ProfileExists(profileName)
}

func (m *manager) createGroup(profileName, parentGroupName, groupName string) (bool, error) {
	return m.profileOps.CreateGroup(profileName, parentGroupName, groupName)
}

func (m *manager) groupExists(profileName, parentGroupName, groupName string) (bool, error) {
	return m.profileOps.GroupExists(profileName, parentGroupName, groupName)
}

func (m *manager) createEntry(profileName, envName, entryPath string) error {
	return m.profileOps.CreateEntry(profileName, envName, entryPath)
}

func (m *manager) entryExists(profileName, envName, entryPath string) (bool, error) {
	return m.profileOps.EntryExists(profileName, envName, entryPath)
}

func (m *manager) getEntriesByEnvironment(profileName, envName string) ([]string, error) {
	return m.profileOps.GetEntriesByEnvironment(profileName, envName)
}

func (m *manager) getRootGroups() ([]string, error) {
	return m.profileOps.GetRootGroups()
}

func (m *manager) getGroupsByParent(parentPath string) ([]string, error) {
	return m.profileOps.GetGroupsByParent(parentPath)
}

func (m *manager) getEntriesByGroup(groupPath string) ([]string, error) {
	return m.profileOps.GetEntriesByGroup(groupPath)
}

func (m *manager) getFieldsByEntry(entryPath string) ([]string, error) {
	return m.profileOps.GetFieldsByEntry(entryPath)
}

func (m *manager) getFieldsByEnvironmentEntry(profileName, envName, entryPath string) ([]string, error) {
	return m.profileOps.GetFieldsByEnvironmentEntry(profileName, envName, entryPath)
}

func (m *manager) getAllFieldsByEnvironmentEntry(profileName, envName, entryPath string) ([]string, error) {
	return m.profileOps.GetAllFieldsByEnvironmentEntry(profileName, envName, entryPath)
}

func (m *manager) isStandardField(fieldName string) bool {
	return m.profileOps.IsStandardField(fieldName)
}

func (m *manager) setStandardField(profileName, envName, entryPath, fieldName, value string) error {
	return m.profileOps.SetStandardField(profileName, envName, entryPath, fieldName, value)
}

func (m *manager) setCustomField(profileName, envName, entryPath, fieldName, value string) error {
	return m.profileOps.SetCustomField(profileName, envName, entryPath, fieldName, value)
}

func (m *manager) createAttachment(profileName, envName, entryPath, attachmentName string, data []byte) error {
	return m.profileOps.CreateAttachment(profileName, envName, entryPath, attachmentName, data)
}

func (m *manager) fieldExists(profileName, envName, entryPath, fieldName string) (bool, error) {
	return m.profileOps.FieldExists(profileName, envName, entryPath, fieldName)
}

// Snapshot operations delegate to snapshot manager
func (m *manager) listProfileTreeGroups(profileName string) ([]string, error) {
	return m.snapshotOps.ListProfileTreeGroups(profileName)
}

func (m *manager) getTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName string) (*common.SecureValue, error) {
	return m.snapshotOps.GetTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName)
}

func (m *manager) cloneTreeGroup(profileName, sourceTreeGroup, targetTreeGroup string) error {
	return m.snapshotOps.CloneTreeGroup(profileName, sourceTreeGroup, targetTreeGroup)
}

func (m *manager) setTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName, value string) error {
	return m.snapshotOps.SetTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName, value)
}

func (m *manager) treeGroupExists(profileName, treeGroup string) (bool, error) {
	return m.snapshotOps.TreeGroupExists(profileName, treeGroup)
}

func (m *manager) renameTreeGroup(profileName, oldName, newName string) error {
	return m.snapshotOps.RenameTreeGroup(profileName, oldName, newName)
}

func (m *manager) deleteTreeGroup(profileName, treeGroup string) error {
	return m.snapshotOps.DeleteTreeGroup(profileName, treeGroup)
}

type sessionManager struct {
	parent *manager
}

func (s *sessionManager) Open(dbPath, keyfilePath, password string) error {
	return s.parent.open(dbPath, keyfilePath, password)
}

func (s *sessionManager) SaveAndClose() error {
	return s.parent.saveAndClose()
}

func (s *sessionManager) CloseWithoutSave() error {
	return s.parent.closeWithoutSave()
}

func (s *sessionManager) IsOpen() bool {
	return s.parent.isOpen()
}

func (s *sessionManager) GetDatabase() *gokeepasslib.Database {
	return s.parent.getDatabase()
}

type databaseManager struct {
	parent *manager
}

func (d *databaseManager) CreateDatabase(dbPath, keyfilePath, password, rootGroupName string) error {
	return d.parent.createDatabase(dbPath, keyfilePath, password, rootGroupName)
}

func (d *databaseManager) GenerateKeyfile(keyfilePath string) error {
	return d.parent.generateKeyfile(keyfilePath)
}

type profileManager struct {
	parent *manager
}

func (p *profileManager) CreateProfile(profileName string) error {
	m := p.parent

	if m.db == nil {
		return fmt.Errorf("database not open")
	}
	if profileName == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if len(m.db.Content.Root.Groups) == 0 {
		return fmt.Errorf("database has no root group")
	}

	rootGroup := &m.db.Content.Root.Groups[0]
	for _, group := range rootGroup.Groups {
		if group.Name == profileName {
			return nil
		}
	}

	profileGroup := gokeepasslib.NewGroup()
	profileGroup.Name = profileName

	headGroup := gokeepasslib.NewGroup()
	headGroup.Name = "HEAD"

	metadataEntry := gokeepasslib.NewEntry()
	metadataEntry.Values = append(metadataEntry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: "metadata"},
	})
	metadataEntry.Values = append(metadataEntry.Values, gokeepasslib.ValueData{
		Key:   "version",
		Value: gokeepasslib.V{Content: "1"},
	})
	datetime := time.Now().Format(time.RFC3339)
	metadataEntry.Values = append(metadataEntry.Values, gokeepasslib.ValueData{
		Key:   "datetime",
		Value: gokeepasslib.V{Content: datetime},
	})

	headGroup.Entries = append(headGroup.Entries, metadataEntry)
	profileGroup.Groups = append(profileGroup.Groups, headGroup)
	rootGroup.Groups = append(rootGroup.Groups, profileGroup)

	// Clear path cache after modification
	m.clearPathCache()

	return nil
}

func (p *profileManager) ProfileExists(profileName string) (bool, error) {
	m := p.parent

	if m.db == nil {
		return false, fmt.Errorf("database not open")
	}
	if profileName == "" {
		return false, fmt.Errorf("profile name cannot be empty")
	}
	if len(m.db.Content.Root.Groups) == 0 {
		return false, nil
	}

	rootGroup := &m.db.Content.Root.Groups[0]
	for _, group := range rootGroup.Groups {
		if group.Name == profileName {
			return true, nil
		}
	}

	return false, nil
}

func (p *profileManager) CreateGroup(profileName, parentGroupName, groupName string) (bool, error) {
	m := p.parent

	if m.db == nil {
		return false, fmt.Errorf("database not open")
	}
	if profileName == "" {
		return false, fmt.Errorf("profile name cannot be empty")
	}
	if parentGroupName == "" {
		return false, fmt.Errorf("parent group name cannot be empty")
	}
	if groupName == "" {
		return false, fmt.Errorf("group name cannot be empty")
	}
	if len(m.db.Content.Root.Groups) == 0 {
		return false, fmt.Errorf("database has no root group")
	}

	rootGroup := &m.db.Content.Root.Groups[0]

	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profileName {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}
	if profileGroup == nil {
		return false, fmt.Errorf("profile '%s' not found", profileName)
	}

	var parentGroup *gokeepasslib.Group
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == parentGroupName {
			parentGroup = &profileGroup.Groups[i]
			break
		}
	}
	if parentGroup == nil {
		return false, fmt.Errorf("parent group '%s' not found in profile '%s'", parentGroupName, profileName)
	}

	for _, group := range parentGroup.Groups {
		if group.Name == groupName {
			return false, nil
		}
	}

	newGroup := gokeepasslib.NewGroup()
	newGroup.Name = groupName
	parentGroup.Groups = append(parentGroup.Groups, newGroup)

	// Clear path cache after modification
	m.clearPathCache()

	return true, nil
}

func (p *profileManager) GroupExists(profileName, parentGroupName, groupName string) (bool, error) {
	m := p.parent

	if m.db == nil {
		return false, fmt.Errorf("database not open")
	}
	if profileName == "" {
		return false, fmt.Errorf("profile name cannot be empty")
	}
	if parentGroupName == "" {
		return false, fmt.Errorf("parent group name cannot be empty")
	}
	if groupName == "" {
		return false, fmt.Errorf("group name cannot be empty")
	}
	if len(m.db.Content.Root.Groups) == 0 {
		return false, nil
	}

	rootGroup := &m.db.Content.Root.Groups[0]

	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profileName {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}
	if profileGroup == nil {
		return false, nil
	}

	var parentGroup *gokeepasslib.Group
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == parentGroupName {
			parentGroup = &profileGroup.Groups[i]
			break
		}
	}
	if parentGroup == nil {
		return false, nil
	}

	for _, group := range parentGroup.Groups {
		if group.Name == groupName {
			return true, nil
		}
	}

	return false, nil
}

func (p *profileManager) CreateEntry(profileName, envName, entryPath string) error {
	m := p.parent

	if m.db == nil {
		return fmt.Errorf("database not open")
	}
	if profileName == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if envName == "" {
		return fmt.Errorf("environment name cannot be empty")
	}
	if entryPath == "" {
		return fmt.Errorf("entry path cannot be empty")
	}
	if len(m.db.Content.Root.Groups) == 0 {
		return fmt.Errorf("database has no root group")
	}

	rootGroup := &m.db.Content.Root.Groups[0]

	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profileName {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}
	if profileGroup == nil {
		return fmt.Errorf("profile '%s' not found", profileName)
	}

	var headGroup *gokeepasslib.Group
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == "HEAD" {
			headGroup = &profileGroup.Groups[i]
			break
		}
	}
	if headGroup == nil {
		return fmt.Errorf("HEAD group not found in profile '%s'", profileName)
	}

	var envGroup *gokeepasslib.Group
	for i := range headGroup.Groups {
		if headGroup.Groups[i].Name == envName {
			envGroup = &headGroup.Groups[i]
			break
		}
	}
	if envGroup == nil {
		return fmt.Errorf("environment '%s' not found in profile '%s'", envName, profileName)
	}

	if len(entryPath) > 0 && entryPath[0] == '/' {
		entryPath = entryPath[1:]
	}
	if entryPath == "" {
		return fmt.Errorf("entry path is empty after parsing")
	}

	components := strings.Split(entryPath, "/")
	if len(components) == 0 {
		return fmt.Errorf("invalid entry path")
	}

	currentGroup := envGroup
	for i := 0; i < len(components)-1; i++ {
		groupName := components[i]
		if groupName == "" {
			continue
		}

		found := false
		for j := range currentGroup.Groups {
			if currentGroup.Groups[j].Name == groupName {
				currentGroup = &currentGroup.Groups[j]
				found = true
				break
			}
		}

		if !found {
			newGroup := gokeepasslib.NewGroup()
			newGroup.Name = groupName
			currentGroup.Groups = append(currentGroup.Groups, newGroup)
			currentGroup = &currentGroup.Groups[len(currentGroup.Groups)-1]
		}
	}

	entryName := components[len(components)-1]
	if entryName == "" {
		return fmt.Errorf("entry name is empty")
	}

	newEntry := gokeepasslib.NewEntry()
	newEntry.Values = append(newEntry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: entryName},
	})

	currentGroup.Entries = append(currentGroup.Entries, newEntry)

	// Clear path cache after modification
	m.clearPathCache()

	return nil
}

func (p *profileManager) EntryExists(profileName, envName, entryPath string) (bool, error) {
	m := p.parent

	if m.db == nil {
		return false, fmt.Errorf("database not open")
	}
	if profileName == "" {
		return false, fmt.Errorf("profile name cannot be empty")
	}
	if envName == "" {
		return false, fmt.Errorf("environment name cannot be empty")
	}
	if entryPath == "" {
		return false, fmt.Errorf("entry path cannot be empty")
	}
	if len(m.db.Content.Root.Groups) == 0 {
		return false, nil
	}

	rootGroup := &m.db.Content.Root.Groups[0]

	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profileName {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}
	if profileGroup == nil {
		return false, nil
	}

	var headGroup *gokeepasslib.Group
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == "HEAD" {
			headGroup = &profileGroup.Groups[i]
			break
		}
	}
	if headGroup == nil {
		return false, nil
	}

	var envGroup *gokeepasslib.Group
	for i := range headGroup.Groups {
		if headGroup.Groups[i].Name == envName {
			envGroup = &headGroup.Groups[i]
			break
		}
	}
	if envGroup == nil {
		return false, nil
	}

	if len(entryPath) > 0 && entryPath[0] == '/' {
		entryPath = entryPath[1:]
	}
	if entryPath == "" {
		return false, fmt.Errorf("entry path is empty after parsing")
	}

	components := strings.Split(entryPath, "/")
	currentGroup := envGroup
	for i := 0; i < len(components)-1; i++ {
		segment := components[i]
		if segment == "" {
			continue
		}

		found := false
		for j := range currentGroup.Groups {
			if currentGroup.Groups[j].Name == segment {
				currentGroup = &currentGroup.Groups[j]
				found = true
				break
			}
		}

		if !found {
			return false, nil
		}
	}

	entryName := components[len(components)-1]
	if entryName == "" {
		return false, fmt.Errorf("entry name is empty")
	}

	for i := range currentGroup.Entries {
		if currentGroup.Entries[i].GetTitle() == entryName {
			return true, nil
		}
	}

	return false, nil
}

func (p *profileManager) GetEntriesByEnvironment(profileName, envName string) ([]string, error) {
	m := p.parent

	if m.db == nil {
		return nil, fmt.Errorf("database not open")
	}
	if profileName == "" {
		return nil, fmt.Errorf("profile name cannot be empty")
	}
	if envName == "" {
		return nil, fmt.Errorf("environment name cannot be empty")
	}
	if len(m.db.Content.Root.Groups) == 0 {
		return []string{}, nil
	}

	rootGroup := &m.db.Content.Root.Groups[0]

	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profileName {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}
	if profileGroup == nil {
		return []string{}, nil
	}

	var headGroup *gokeepasslib.Group
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == "HEAD" {
			headGroup = &profileGroup.Groups[i]
			break
		}
	}
	if headGroup == nil {
		return []string{}, nil
	}

	var envGroup *gokeepasslib.Group
	for i := range headGroup.Groups {
		if headGroup.Groups[i].Name == envName {
			envGroup = &headGroup.Groups[i]
			break
		}
	}
	if envGroup == nil {
		return []string{}, nil
	}

	var entries []string
	collectEntries(envGroup, "", &entries)
	return entries, nil
}

func (p *profileManager) GetRootGroups() ([]string, error) {
	m := p.parent

	if m.db == nil {
		return nil, fmt.Errorf("database not open")
	}
	if len(m.db.Content.Root.Groups) == 0 {
		return []string{}, nil
	}

	rootGroup := m.db.Content.Root.Groups[0]
	groups := make([]string, 0, len(rootGroup.Groups))
	for _, group := range rootGroup.Groups {
		groups = append(groups, group.Name)
	}

	return groups, nil
}

func (p *profileManager) GetGroupsByParent(parentPath string) ([]string, error) {
	m := p.parent

	if m.db == nil {
		return nil, fmt.Errorf("database not open")
	}

	parentGroup, err := m.findGroupByPath(parentPath)
	if err != nil {
		return nil, err
	}

	groups := make([]string, 0, len(parentGroup.Groups))
	for _, group := range parentGroup.Groups {
		groups = append(groups, group.Name)
	}

	return groups, nil
}

func (p *profileManager) GetEntriesByGroup(groupPath string) ([]string, error) {
	m := p.parent

	if m.db == nil {
		return nil, fmt.Errorf("database not open")
	}

	group, err := m.findGroupByPath(groupPath)
	if err != nil {
		return nil, err
	}

	entries := make([]string, 0, len(group.Entries))
	for _, entry := range group.Entries {
		var title string
		for _, value := range entry.Values {
			if value.Key == "Title" {
				title = value.Value.Content
				break
			}
		}
		if title != "" {
			entries = append(entries, title)
		}
	}

	return entries, nil
}

func (p *profileManager) GetFieldsByEntry(entryPath string) ([]string, error) {
	m := p.parent

	if m.db == nil {
		return nil, fmt.Errorf("database not open")
	}

	entry, err := m.findEntryByPath(entryPath)
	if err != nil {
		return nil, err
	}

	fields := make([]string, 0, len(entry.Values))
	for _, value := range entry.Values {
		if value.Key != "" {
			fields = append(fields, value.Key)
		}
	}

	return fields, nil
}

func (p *profileManager) GetFieldsByEnvironmentEntry(profileName, envName, entryPath string) ([]string, error) {
	entry, err := p.findEnvironmentEntry(profileName, envName, entryPath)
	if err != nil {
		return nil, err
	}

	var fields []string
	for _, value := range entry.Values {
		if value.Key == "Title" {
			continue
		}
		if value.Value.Content != "" {
			fields = append(fields, value.Key)
		}
	}
	for _, binary := range entry.Binaries {
		fields = append(fields, "attachments/"+binary.Name)
	}

	return fields, nil
}

func (p *profileManager) GetAllFieldsByEnvironmentEntry(profileName, envName, entryPath string) ([]string, error) {
	entry, err := p.findEnvironmentEntry(profileName, envName, entryPath)
	if err != nil {
		return nil, err
	}

	var fields []string
	for _, value := range entry.Values {
		if value.Key == "Title" {
			continue
		}
		fields = append(fields, value.Key)
	}
	for _, binary := range entry.Binaries {
		fields = append(fields, "attachments/"+binary.Name)
	}

	return fields, nil
}

func (p *profileManager) IsStandardField(fieldName string) bool {
	standardFields := []string{"Title", "UserName", "Password", "URL", "Notes"}
	fieldLower := strings.ToLower(fieldName)

	for _, standard := range standardFields {
		if strings.ToLower(standard) == fieldLower {
			return true
		}
	}

	return false
}

func (p *profileManager) SetStandardField(profileName, envName, entryPath, fieldName, value string) error {
	if !p.IsStandardField(fieldName) {
		return fmt.Errorf("'%s' is not a standard field", fieldName)
	}

	entry, err := p.findEnvironmentEntry(profileName, envName, entryPath)
	if err != nil {
		return err
	}

	standardFields := map[string]string{
		"title":    "Title",
		"username": "UserName",
		"password": "Password",
		"url":      "URL",
		"notes":    "Notes",
	}
	normalizedFieldName := standardFields[strings.ToLower(fieldName)]

	for i := range entry.Values {
		if entry.Values[i].Key == normalizedFieldName {
			entry.Values[i].Value.Content = value
			return nil
		}
	}

	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   normalizedFieldName,
		Value: gokeepasslib.V{Content: value},
	})

	// Clear path cache after modification
	p.parent.clearPathCache()

	return nil
}

func (p *profileManager) SetCustomField(profileName, envName, entryPath, fieldName, value string) error {
	if fieldName == "" {
		return fmt.Errorf("field name cannot be empty")
	}
	if p.IsStandardField(fieldName) {
		return fmt.Errorf("'%s' is a standard field, use SetStandardField instead", fieldName)
	}

	entry, err := p.findEnvironmentEntry(profileName, envName, entryPath)
	if err != nil {
		return err
	}

	for i := range entry.Values {
		if entry.Values[i].Key == fieldName {
			entry.Values[i].Value.Content = value
			return nil
		}
	}

	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   fieldName,
		Value: gokeepasslib.V{Content: value},
	})

	// Clear path cache after modification
	p.parent.clearPathCache()

	return nil
}

func (p *profileManager) CreateAttachment(profileName, envName, entryPath, attachmentName string, data []byte) error {
	if attachmentName == "" {
		return fmt.Errorf("attachment name cannot be empty")
	}
	if data == nil {
		return fmt.Errorf("attachment data cannot be nil")
	}

	entry, err := p.findEnvironmentEntry(profileName, envName, entryPath)
	if err != nil {
		return err
	}

	// Check if attachment already exists - if so, do nothing (don't replace)
	for _, binary := range entry.Binaries {
		if binary.Name == attachmentName {
			return nil
		}
	}

	m := p.parent
	// Use AddBinary to add the binary to the database
	// This method handles format version differences (KDBX v3 vs v4)
	addedBinary := m.db.AddBinary(data)
	if addedBinary == nil {
		return fmt.Errorf("failed to add binary to database")
	}

	// Create a reference to the binary in the entry
	entry.Binaries = append(entry.Binaries, gokeepasslib.NewBinaryReference(attachmentName, addedBinary.ID))

	// Clear path cache after modification
	m.clearPathCache()

	return nil
}

// DeleteAttachment removes an attachment from an entry
func (p *profileManager) DeleteAttachment(profileName, envName, entryPath, attachmentName string) error {
	if attachmentName == "" {
		return fmt.Errorf("attachment name cannot be empty")
	}

	entry, err := p.findEnvironmentEntry(profileName, envName, entryPath)
	if err != nil {
		return err
	}

	// Check if attachment exists
	found := false
	for _, binary := range entry.Binaries {
		if binary.Name == attachmentName {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("attachment '%s' not found in entry '%s'", attachmentName, entryPath)
	}

	// Remove the attachment from the entry by filtering in-place
	// We must modify the slice in-place, not reassign it, because entry is a pointer
	// and reassigning entry.Binaries would only change the local reference
	n := 0
	for _, binary := range entry.Binaries {
		if binary.Name != attachmentName {
			entry.Binaries[n] = binary
			n++
		}
	}
	entry.Binaries = entry.Binaries[:n]

	m := p.parent
	// Clear path cache after modification
	m.clearPathCache()

	return nil
}

func (p *profileManager) FieldExists(profileName, envName, entryPath, fieldName string) (bool, error) {
	if fieldName == "" {
		return false, fmt.Errorf("field name cannot be empty")
	}

	entry, err := p.findEnvironmentEntry(profileName, envName, entryPath)
	if err != nil {
		return false, err
	}

	if strings.HasPrefix(fieldName, "attachments/") {
		attachmentName := strings.TrimPrefix(fieldName, "attachments/")
		for _, binary := range entry.Binaries {
			if binary.Name == attachmentName {
				return true, nil
			}
		}
		return false, nil
	}

	isStandard := p.IsStandardField(fieldName)
	for _, value := range entry.Values {
		if isStandard {
			if strings.EqualFold(value.Key, fieldName) {
				return true, nil
			}
			continue
		}
		if value.Key == fieldName {
			return true, nil
		}
	}

	return false, nil
}

// GetFieldValue retrieves the value of a specific field in an entry
func (p *profileManager) GetFieldValue(profileName, envName, entryPath, fieldName string) (string, error) {
	if fieldName == "" {
		return "", fmt.Errorf("field name cannot be empty")
	}

	entry, err := p.findEnvironmentEntry(profileName, envName, entryPath)
	if err != nil {
		return "", err
	}

	// Check if it's an attachment
	if strings.HasPrefix(fieldName, "attachments/") {
		return "", fmt.Errorf("cannot get value from attachment field: %s", fieldName)
	}

	// Search for the field
	isStandard := p.IsStandardField(fieldName)
	for _, value := range entry.Values {
		if isStandard {
			if strings.EqualFold(value.Key, fieldName) {
				return value.Value.Content, nil
			}
			continue
		}
		if value.Key == fieldName {
			return value.Value.Content, nil
		}
	}

	return "", fmt.Errorf("field '%s' not found in entry '%s'", fieldName, entryPath)
}

// GetAttachmentContent retrieves the content of a specific attachment in an entry
func (p *profileManager) GetAttachmentContent(profileName, envName, entryPath, attachmentName string) ([]byte, error) {
	if attachmentName == "" {
		return nil, fmt.Errorf("attachment name cannot be empty")
	}

	entry, err := p.findEnvironmentEntry(profileName, envName, entryPath)
	if err != nil {
		return nil, err
	}

	// Search for the attachment
	for _, binary := range entry.Binaries {
		if binary.Name == attachmentName {
			// Get the binary ID from the reference
			binaryID := binary.Value.ID
			
			// Use FindBinary which handles format version differences
			dbBinary := p.parent.db.FindBinary(binaryID)
			if dbBinary == nil {
				return nil, fmt.Errorf("attachment '%s' content not found in database (ID: %d)", attachmentName, binaryID)
			}

			// For KDBX v4, content is stored RAW (not base64 encoded)
			// For KDBX v3, content is base64 encoded
			// Read directly from Content field to avoid GetContentBytes() base64 decode bug
			content := dbBinary.Content
			
			// Handle compression if enabled (both KDBX 3 and 4 support this)
			if dbBinary.Compressed.Bool {
				reader, err := gzip.NewReader(bytes.NewReader(content))
				if err != nil {
					return nil, fmt.Errorf("failed to decompress attachment '%s': %w", attachmentName, err)
				}
				defer reader.Close()
				content, err = io.ReadAll(reader)
				if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
					return nil, fmt.Errorf("failed to read compressed attachment '%s': %w", attachmentName, err)
				}
			}
			
			return content, nil
		}
	}

	return nil, fmt.Errorf("attachment '%s' not found in entry '%s'", attachmentName, entryPath)
}

func (p *profileManager) findEnvironmentEntry(profileName, envName, entryPath string) (*gokeepasslib.Entry, error) {
	if entryPath == "" {
		return nil, fmt.Errorf("entry path cannot be empty")
	}

	envGroup, err := p.getEnvironmentGroup(profileName, envName)
	if err != nil {
		return nil, err
	}

	entry, err := findEntryByPath(envGroup, entryPath)
	if err != nil {
		return nil, err
	}

	return entry, nil
}

func (p *profileManager) getEnvironmentGroup(profileName, envName string) (*gokeepasslib.Group, error) {
	m := p.parent
	if m.db == nil {
		return nil, fmt.Errorf("database not open")
	}
	if profileName == "" {
		return nil, fmt.Errorf("profile name cannot be empty")
	}
	if envName == "" {
		return nil, fmt.Errorf("environment name cannot be empty")
	}
	if len(m.db.Content.Root.Groups) == 0 {
		return nil, fmt.Errorf("root group not found")
	}

	rootGroup := &m.db.Content.Root.Groups[0]

	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profileName {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}
	if profileGroup == nil {
		return nil, fmt.Errorf("profile '%s' not found", profileName)
	}

	var headGroup *gokeepasslib.Group
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == "HEAD" {
			headGroup = &profileGroup.Groups[i]
			break
		}
	}
	if headGroup == nil {
		return nil, fmt.Errorf("HEAD group not found in profile '%s'", profileName)
	}

	for i := range headGroup.Groups {
		if headGroup.Groups[i].Name == envName {
			return &headGroup.Groups[i], nil
		}
	}

	return nil, fmt.Errorf("environment '%s' not found in profile '%s'", envName, profileName)
}

type snapshotManager struct {
	parent *manager
}

func (s *snapshotManager) ListProfileTreeGroups(profileName string) ([]string, error) {
	m := s.parent
	if m.db == nil {
		return nil, fmt.Errorf("database not open")
	}
	if profileName == "" {
		return nil, fmt.Errorf("profile name cannot be empty")
	}
	if len(m.db.Content.Root.Groups) == 0 {
		return nil, fmt.Errorf("no groups in database")
	}

	profileGroup, err := findGroupByName(&m.db.Content.Root.Groups[0], profileName)
	if err != nil {
		return nil, fmt.Errorf("profile '%s' not found: %w", profileName, err)
	}

	treeGroups := make([]string, 0, len(profileGroup.Groups))
	for _, group := range profileGroup.Groups {
		treeGroups = append(treeGroups, group.Name)
	}

	return treeGroups, nil
}

func (s *snapshotManager) GetTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName string) (*common.SecureValue, error) {
	m := s.parent
	if m.db == nil {
		return nil, fmt.Errorf("database not open")
	}
	if profileName == "" {
		return nil, fmt.Errorf("profile name cannot be empty")
	}
	if treeGroup == "" {
		return nil, fmt.Errorf("tree group name cannot be empty")
	}
	if entryPath == "" {
		return nil, fmt.Errorf("entry path cannot be empty")
	}
	if fieldName == "" {
		return nil, fmt.Errorf("field name cannot be empty")
	}
	if len(m.db.Content.Root.Groups) == 0 {
		return nil, fmt.Errorf("no groups in database")
	}

	profileGroup, err := findGroupByName(&m.db.Content.Root.Groups[0], profileName)
	if err != nil {
		return nil, fmt.Errorf("profile '%s' not found: %w", profileName, err)
	}

	treeGroupObj, err := findGroupByName(profileGroup, treeGroup)
	if err != nil {
		return nil, fmt.Errorf("tree group '%s' not found in profile '%s': %w", treeGroup, profileName, err)
	}

	entry, err := findEntryByPath(treeGroupObj, entryPath)
	if err != nil {
		return nil, fmt.Errorf("entry '%s' not found in tree group '%s': %w", entryPath, treeGroup, err)
	}

	isStandard := m.profileOps.IsStandardField(fieldName)
	for _, value := range entry.Values {
		if isStandard {
			if strings.EqualFold(value.Key, fieldName) {
				return common.NewSecureValue(value.Value.Content), nil
			}
			continue
		}
		if value.Key == fieldName {
			return common.NewSecureValue(value.Value.Content), nil
		}
	}

	return nil, fmt.Errorf("field '%s' not found in entry '%s'", fieldName, entryPath)
}

func (s *snapshotManager) CloneTreeGroup(profileName, sourceTreeGroup, targetTreeGroup string) error {
	m := s.parent
	if m.db == nil {
		return fmt.Errorf("database not open")
	}
	if profileName == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if sourceTreeGroup == "" {
		return fmt.Errorf("source tree group cannot be empty")
	}
	if targetTreeGroup == "" {
		return fmt.Errorf("target tree group cannot be empty")
	}
	if len(m.db.Content.Root.Groups) == 0 {
		return fmt.Errorf("no groups in database")
	}

	profileGroup, err := findGroupByName(&m.db.Content.Root.Groups[0], profileName)
	if err != nil {
		return fmt.Errorf("profile '%s' not found: %w", profileName, err)
	}

	sourceGroup, err := findGroupByName(profileGroup, sourceTreeGroup)
	if err != nil {
		return fmt.Errorf("source tree group '%s' not found in profile '%s': %w", sourceTreeGroup, profileName, err)
	}

	if _, err = findGroupByName(profileGroup, targetTreeGroup); err == nil {
		return fmt.Errorf("target tree group '%s' already exists in profile '%s'", targetTreeGroup, profileName)
	}

	clonedGroup := deepCloneGroup(sourceGroup)
	clonedGroup.Name = targetTreeGroup
	profileGroup.Groups = append(profileGroup.Groups, clonedGroup)

	// Clear path cache after modification
	m.clearPathCache()

	return nil
}

func (s *snapshotManager) SetTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName, value string) error {
	m := s.parent
	if m.db == nil {
		return fmt.Errorf("database not open")
	}
	if profileName == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if treeGroup == "" {
		return fmt.Errorf("tree group cannot be empty")
	}
	if entryPath == "" {
		return fmt.Errorf("entry path cannot be empty")
	}
	if fieldName == "" {
		return fmt.Errorf("field name cannot be empty")
	}
	if len(m.db.Content.Root.Groups) == 0 {
		return fmt.Errorf("no groups in database")
	}

	profileGroup, err := findGroupByName(&m.db.Content.Root.Groups[0], profileName)
	if err != nil {
		return fmt.Errorf("profile '%s' not found: %w", profileName, err)
	}

	treeGroupObj, err := findGroupByName(profileGroup, treeGroup)
	if err != nil {
		return fmt.Errorf("tree group '%s' not found in profile '%s': %w", treeGroup, profileName, err)
	}

	entry, err := findEntryByPath(treeGroupObj, entryPath)
	if err != nil {
		return fmt.Errorf("entry '%s' not found in tree group '%s': %w", entryPath, treeGroup, err)
	}

	isStandard := m.profileOps.IsStandardField(fieldName)
	fieldFound := false
	for i := range entry.Values {
		if isStandard {
			if strings.EqualFold(entry.Values[i].Key, fieldName) {
				entry.Values[i].Value.Content = value
				fieldFound = true
				break
			}
			continue
		}
		if entry.Values[i].Key == fieldName {
			entry.Values[i].Value.Content = value
			fieldFound = true
			break
		}
	}

	if !fieldFound {
		entry.Values = append(entry.Values, gokeepasslib.ValueData{
			Key:   fieldName,
			Value: gokeepasslib.V{Content: value},
		})
	}

	// Clear path cache after modification
	m.clearPathCache()

	return nil
}

func (s *snapshotManager) TreeGroupExists(profileName, treeGroup string) (bool, error) {
	m := s.parent
	if m.db == nil {
		return false, fmt.Errorf("database not open")
	}
	if profileName == "" {
		return false, fmt.Errorf("profile name cannot be empty")
	}
	if treeGroup == "" {
		return false, fmt.Errorf("tree group name cannot be empty")
	}
	if len(m.db.Content.Root.Groups) == 0 {
		return false, nil
	}

	rootGroup := &m.db.Content.Root.Groups[0]
	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profileName {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}
	if profileGroup == nil {
		return false, nil
	}

	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == treeGroup {
			return true, nil
		}
	}

	return false, nil
}

func (s *snapshotManager) RenameTreeGroup(profileName, oldName, newName string) error {
	m := s.parent
	if m.db == nil {
		return fmt.Errorf("database not open")
	}
	if profileName == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if oldName == "" {
		return fmt.Errorf("old name cannot be empty")
	}
	if newName == "" {
		return fmt.Errorf("new name cannot be empty")
	}
	if len(m.db.Content.Root.Groups) == 0 {
		return fmt.Errorf("root group not found")
	}

	rootGroup := &m.db.Content.Root.Groups[0]
	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profileName {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}
	if profileGroup == nil {
		return fmt.Errorf("profile '%s' not found", profileName)
	}

	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == oldName {
			profileGroup.Groups[i].Name = newName

			// Clear path cache after modification
			m.clearPathCache()

			return nil
		}
	}

	return fmt.Errorf("tree group '%s' not found in profile '%s'", oldName, profileName)
}

func (s *snapshotManager) DeleteTreeGroup(profileName, treeGroup string) error {
	m := s.parent
	if m.db == nil {
		return fmt.Errorf("database not open")
	}
	if profileName == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if treeGroup == "" {
		return fmt.Errorf("tree group name cannot be empty")
	}
	if len(m.db.Content.Root.Groups) == 0 {
		return fmt.Errorf("root group not found")
	}

	rootGroup := &m.db.Content.Root.Groups[0]
	var profileGroup *gokeepasslib.Group
	for i := range rootGroup.Groups {
		if rootGroup.Groups[i].Name == profileName {
			profileGroup = &rootGroup.Groups[i]
			break
		}
	}
	if profileGroup == nil {
		return fmt.Errorf("profile '%s' not found", profileName)
	}

	index := -1
	for i := range profileGroup.Groups {
		if profileGroup.Groups[i].Name == treeGroup {
			index = i
			break
		}
	}
	if index == -1 {
		return fmt.Errorf("tree group '%s' not found in profile '%s'", treeGroup, profileName)
	}

	profileGroup.Groups = append(profileGroup.Groups[:index], profileGroup.Groups[index+1:]...)

	// Clear path cache after modification
	m.clearPathCache()

	return nil
}

// clearPassword securely overwrites password in memory
func (m *manager) clearPassword() {
	if m.password != nil {
		// Overwrite with zeros before releasing
		for i := range m.password {
			m.password[i] = 0
		}
		m.password = nil
	}
}

// Open opens a KeePass database and keeps it in memory
// Must be called before any database operations
func (m *manager) open(dbPath, keyfilePath, password string) error {
	if m.db != nil {
		return fmt.Errorf("database already open")
	}

	// Validate input
	if dbPath == "" {
		return fmt.Errorf("database path cannot be empty")
	}
	if keyfilePath == "" {
		return fmt.Errorf("keyfile path cannot be empty")
	}
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	// Sanitize paths
	sanitizedDBPath, err := m.sanitizePath(dbPath)
	if err != nil {
		return fmt.Errorf("invalid database path: %w", err)
	}
	sanitizedKeyfilePath, err := m.sanitizePath(keyfilePath)
	if err != nil {
		return fmt.Errorf("invalid keyfile path: %w", err)
	}

	// Open database file
	file, err := m.fs.Open(sanitizedDBPath)
	if err != nil {
		return fmt.Errorf("failed to open database file: %w", err)
	}
	defer file.Close()

	// Create credentials
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, sanitizedKeyfilePath)
	if err != nil {
		return fmt.Errorf("failed to create credentials: %w", err)
	}

	// Decode database
	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials
	err = gokeepasslib.NewDecoder(file).Decode(db)
	if err != nil {
		return fmt.Errorf("failed to decode database: %w", err)
	}

	// Unlock database
	err = db.UnlockProtectedEntries()
	if err != nil {
		return fmt.Errorf("failed to unlock database: %w", err)
	}

	// Store session
	m.db = db
	m.dbPath = sanitizedDBPath
	m.keyfilePath = sanitizedKeyfilePath
	m.password = []byte(password) // Convert string to []byte for secure cleanup

	return nil
}

// SaveAndClose saves changes and closes the database session
func (m *manager) SaveAndClose() error {
	if m.db == nil {
		return fmt.Errorf("no database open")
	}

	// Lock protected entries
	err := m.db.LockProtectedEntries()
	if err != nil {
		// Clear session even on error
		m.db = nil
		m.dbPath = ""
		m.keyfilePath = ""
		m.clearPassword()
		return fmt.Errorf("failed to lock database: %w", err)
	}

	// Open file for writing with secure permissions
	file, err := m.fs.OpenFile(m.dbPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		// Clear session even on error
		m.db = nil
		m.dbPath = ""
		m.keyfilePath = ""
		m.clearPassword()
		return fmt.Errorf("failed to open database file for writing: %w", err)
	}
	defer file.Close()

	// Encode and save
	keepassEncoder := gokeepasslib.NewEncoder(file)
	err = keepassEncoder.Encode(m.db)
	if err != nil {
		// Clear session even on error
		m.db = nil
		m.dbPath = ""
		m.keyfilePath = ""
		m.clearPassword()
		return fmt.Errorf("failed to encode database: %w", err)
	}

	// Clear session
	m.db = nil
	m.dbPath = ""
	m.keyfilePath = ""
	m.clearPassword()

	return nil
}

// CloseWithoutSave closes the database session without saving changes
func (m *manager) CloseWithoutSave() error {
	if m.db == nil {
		return fmt.Errorf("no database open")
	}

	// Clear session without saving
	m.db = nil
	m.dbPath = ""
	m.keyfilePath = ""
	m.clearPassword()

	return nil
}

// IsOpen returns true if a database session is currently open
func (m *manager) IsOpen() bool {
	return m.db != nil
}

// GetDatabase returns the currently open database
// Returns nil if no database is open
func (m *manager) getDatabase() *gokeepasslib.Database {
	return m.db
}

// sanitizePath cleans and validates a file path to prevent path traversal attacks
func sanitizePath(path string) (string, error) {
	temp := &manager{fs: osFileSystemAdapter{}}
	return temp.sanitizePath(path)
}

func (m *manager) sanitizePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path cannot be empty")
	}

	// Check for path traversal attempts BEFORE cleaning
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("path contains invalid '..' components")
	}

	// Clean the path to resolve any . or .. components
	cleanPath := filepath.Clean(path)

	// Additional check: ensure the path doesn't start with .. after cleaning
	if strings.HasPrefix(cleanPath, "..") {
		return "", fmt.Errorf("path traversal detected")
	}

	// Validate symlinks: ensure the path doesn't traverse outside intended directory
	// Get absolute path to evaluate symlinks
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Evaluate symlinks (resolve to final target)
	evalPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		// If symlink doesn't exist yet, that's OK (file creation case)
		// Check if it's because the file doesn't exist
		if m.fs.IsNotExist(err) {
			// For non-existent paths, check parent directory instead
			parentDir := filepath.Dir(absPath)
			if parentDir != "" && parentDir != "." {
				evalParent, err := filepath.EvalSymlinks(parentDir)
				if err != nil && !m.fs.IsNotExist(err) {
					return "", fmt.Errorf("failed to evaluate parent directory symlinks: %w", err)
				}
				// Reconstruct path with evaluated parent
				if evalParent != "" {
					evalPath = filepath.Join(evalParent, filepath.Base(absPath))
				} else {
					evalPath = absPath
				}
			} else {
				evalPath = absPath
			}
		} else {
			return "", fmt.Errorf("failed to evaluate symlinks: %w", err)
		}
	}

	// Additional security: ensure resolved path doesn't escape to dangerous locations
	// This prevents symlink attacks pointing to /etc/passwd, /root/, etc.
	if strings.HasPrefix(evalPath, "/etc/") ||
		strings.HasPrefix(evalPath, "/root/") ||
		strings.HasPrefix(evalPath, "/sys/") ||
		strings.HasPrefix(evalPath, "/proc/") {
		return "", fmt.Errorf("path resolves to forbidden system directory")
	}

	return cleanPath, nil
}

// GenerateKeyfile generates a cryptographically secure keyfile
// Uses 64 bytes (512 bits) for military-grade security
func (m *manager) GenerateKeyfile(keyfilePath string) error {
	// Validate input parameters
	if keyfilePath == "" {
		return fmt.Errorf("keyfile path cannot be empty")
	}

	// Sanitize path to prevent traversal attacks
	sanitizedPath, err := m.sanitizePath(keyfilePath)
	if err != nil {
		return fmt.Errorf("invalid keyfile path: %w", err)
	}

	// Generate 64 random bytes using crypto/rand (CSPRNG)
	keyData := make([]byte, 64)
	_, err = rand.Read(keyData)
	if err != nil {
		return fmt.Errorf("failed to generate random key data: %w", err)
	}

	// Write keyfile to disk
	err = m.fs.WriteFile(sanitizedPath, keyData, 0600)
	if err != nil {
		return fmt.Errorf("failed to write keyfile: %w", err)
	}

	return nil
}

// CreateDatabase creates a new KeePass database in KDBX4 format
// Protected with both password and keyfile
func (m *manager) createDatabase(dbPath, keyfilePath, password, rootGroupName string) error {
	// Validate input parameters
	if dbPath == "" {
		return fmt.Errorf("database path cannot be empty")
	}
	if keyfilePath == "" {
		return fmt.Errorf("keyfile path cannot be empty")
	}
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}
	if rootGroupName == "" {
		return fmt.Errorf("root group name cannot be empty")
	}

	// Sanitize paths to prevent traversal attacks
	sanitizedDbPath, err := m.sanitizePath(dbPath)
	if err != nil {
		return fmt.Errorf("invalid database path: %w", err)
	}
	sanitizedKeyfilePath, err := m.sanitizePath(keyfilePath)
	if err != nil {
		return fmt.Errorf("invalid keyfile path: %w", err)
	}

	// Create new database in KDBX4 format
	db := gokeepasslib.NewDatabase(
		gokeepasslib.WithDatabaseKDBXVersion4(),
	)

	// Create credentials with password and keyfile
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, sanitizedKeyfilePath)
	if err != nil {
		return fmt.Errorf("failed to create credentials: %w", err)
	}

	// Assign credentials to database
	db.Credentials = credentials

	// Create root group with custom name if provided
	if rootGroupName != "" {
		rootGroup := gokeepasslib.NewGroup()
		rootGroup.Name = rootGroupName
		db.Content.Root.Groups = []gokeepasslib.Group{rootGroup}
	}

	// Lock protected entries (encrypt sensitive data)
	err = db.LockProtectedEntries()
	if err != nil {
		return fmt.Errorf("failed to lock protected entries: %w", err)
	}

	// Save database to file with restrictive permissions (0600)
	file, err := m.fs.OpenFile(sanitizedDbPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create database file: %w", err)
	}
	defer file.Close()

	// Create encoder and encode database
	encoder := gokeepasslib.NewEncoder(file)
	err = encoder.Encode(db)
	if err != nil {
		return fmt.Errorf("failed to encode database: %w", err)
	}

	return nil
}

// OpenDatabase opens an existing KeePass database
// Returns unlocked database or error if credentials are invalid
func (m *manager) OpenDatabase(dbPath, keyfilePath, password string) (*gokeepasslib.Database, error) {
	// Validate input parameters
	if dbPath == "" {
		return nil, fmt.Errorf("database path cannot be empty")
	}
	if keyfilePath == "" {
		return nil, fmt.Errorf("keyfile path cannot be empty")
	}
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}

	// Sanitize paths to prevent traversal attacks
	sanitizedDbPath, err := m.sanitizePath(dbPath)
	if err != nil {
		return nil, fmt.Errorf("invalid database path: %w", err)
	}
	sanitizedKeyfilePath, err := m.sanitizePath(keyfilePath)
	if err != nil {
		return nil, fmt.Errorf("invalid keyfile path: %w", err)
	}

	// Create credentials FIRST - needed for decoding encrypted database
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, sanitizedKeyfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create credentials: %w", err)
	}

	// Read database file
	file, err := m.fs.Open(sanitizedDbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database file: %w", err)
	}
	defer file.Close()

	// Create database and assign credentials BEFORE decoding
	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials

	// Decode database (will use credentials to decrypt)
	decoder := gokeepasslib.NewDecoder(file)
	err = decoder.Decode(db)
	if err != nil {
		return nil, fmt.Errorf("failed to decode database: %w", err)
	}

	// Unlock protected entries (decrypt sensitive fields)
	err = db.UnlockProtectedEntries()
	if err != nil {
		return nil, fmt.Errorf("failed to unlock database (wrong password or keyfile): %w", err)
	}

	return db, nil
}

// ProfileExists checks if a profile group exists in the database
func (m *manager) ProfileExists(profileName string) (bool, error) {
	return m.profileOps.ProfileExists(profileName)
}

// GroupExists checks if a group exists under a parent group within a profile
func (m *manager) GroupExists(profileName, parentGroupName, groupName string) (bool, error) {
	return m.profileOps.GroupExists(profileName, parentGroupName, groupName)
}

// CreateProfile creates a new profile structure in the database:
// Profile (group) → HEAD (group) → metadata (entry)
func (m *manager) CreateProfile(profileName string) error {
	return m.profileOps.CreateProfile(profileName)
}

// CreateGroup creates a new group under a parent group within a profile
// Path: Profile > ParentGroup > NewGroup
// Returns (true, nil) if group was created, (false, nil) if already existed
// Idempotent: if group already exists, returns (false, nil) without error
func (m *manager) CreateGroup(profileName, parentGroupName, groupName string) (bool, error) {
	return m.profileOps.CreateGroup(profileName, parentGroupName, groupName)
}

// CreateEntry creates a new entry in the database under a specific environment
// Creates intermediate groups automatically if they don't exist
// Entry is created empty (no custom fields)
func (m *manager) CreateEntry(profileName, envName, entryPath string) error {
	return m.profileOps.CreateEntry(profileName, envName, entryPath)
}

// EntryExists checks if an entry exists at the specified path within an environment
func (m *manager) EntryExists(profileName, envName, entryPath string) (bool, error) {
	return m.profileOps.EntryExists(profileName, envName, entryPath)
}

// GetEntriesByEnvironment retrieves all entry paths within a specific environment
// Returns paths relative to the environment (without environment prefix)
func (m *manager) GetEntriesByEnvironment(profileName, envName string) ([]string, error) {
	return m.profileOps.GetEntriesByEnvironment(profileName, envName)
}

// collectEntries recursively collects all entry paths in a group
func collectEntries(group *gokeepasslib.Group, currentPath string, entries *[]string) {
	// Collect entries in current group
	for _, entry := range group.Entries {
		// Get entry title
		var title string
		for _, value := range entry.Values {
			if value.Key == "Title" {
				title = value.Value.Content
				break
			}
		}

		if title != "" {
			var entryPath string
			if currentPath == "" {
				entryPath = title
			} else {
				entryPath = currentPath + "/" + title
			}
			*entries = append(*entries, entryPath)
		}
	}

	// Recursively process subgroups
	for i := range group.Groups {
		subGroupName := group.Groups[i].Name
		var newPath string
		if currentPath == "" {
			newPath = subGroupName
		} else {
			newPath = currentPath + "/" + subGroupName
		}
		collectEntries(&group.Groups[i], newPath, entries)
	}
}

// GetRootGroups returns the names of all groups directly under the root
func (m *manager) GetRootGroups() ([]string, error) {
	return m.profileOps.GetRootGroups()
}

// GetGroupsByParent returns the names of all groups directly under the specified parent path
func (m *manager) GetGroupsByParent(parentPath string) ([]string, error) {
	return m.profileOps.GetGroupsByParent(parentPath)
}

// GetEntriesByGroup returns the names of all entries directly under the specified group path
func (m *manager) GetEntriesByGroup(groupPath string) ([]string, error) {
	return m.profileOps.GetEntriesByGroup(groupPath)
}

// GetFieldsByEntry returns all field names (standard and custom) for the specified entry path
func (m *manager) GetFieldsByEntry(entryPath string) ([]string, error) {
	return m.profileOps.GetFieldsByEntry(entryPath)
}

// GetFieldsByEnvironmentEntry returns all field names (standard and custom) and attachments
// for the specified entry within a profile and environment
func (m *manager) GetFieldsByEnvironmentEntry(profileName, envName, entryPath string) ([]string, error) {
	return m.profileOps.GetFieldsByEnvironmentEntry(profileName, envName, entryPath)
}

// GetAllFieldsByEnvironmentEntry returns ALL field names (standard and custom) and attachments
// for the specified entry within a profile and environment, including empty fields
func (m *manager) GetAllFieldsByEnvironmentEntry(profileName, envName, entryPath string) ([]string, error) {
	return m.profileOps.GetAllFieldsByEnvironmentEntry(profileName, envName, entryPath)
}

// findGroupByPath finds a group by its full path
func (m *manager) findGroupByPath(path string) (*gokeepasslib.Group, error) {
	if path == "" {
		// Root group
		if len(m.db.Content.Root.Groups) == 0 {
			return nil, fmt.Errorf("root group not found")
		}
		return &m.db.Content.Root.Groups[0], nil
	}

	parts := m.splitPath(path)
	current := &m.db.Content.Root.Groups[0]

	for _, part := range parts {
		found := false
		for i := range current.Groups {
			if current.Groups[i].Name == part {
				current = &current.Groups[i]
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("group '%s' not found in path '%s'", part, path)
		}
	}

	return current, nil
}

// findEntryByPath finds an entry by its full path
func (m *manager) findEntryByPath(path string) (*gokeepasslib.Entry, error) {
	parts := m.splitPath(path)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid entry path: %s", path)
	}

	groupPath := strings.Join(parts[:len(parts)-1], "/")
	entryName := parts[len(parts)-1]

	group, err := m.findGroupByPath(groupPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range group.Entries {
		var title string
		for _, value := range entry.Values {
			if value.Key == "Title" {
				title = value.Value.Content
				break
			}
		}
		if title == entryName {
			return &entry, nil
		}
	}

	return nil, fmt.Errorf("entry '%s' not found in group '%s'", entryName, groupPath)
}
func findGroupByName(parentGroup *gokeepasslib.Group, groupName string) (*gokeepasslib.Group, error) {
	if parentGroup == nil {
		return nil, fmt.Errorf("parent group is nil")
	}

	for i := range parentGroup.Groups {
		if parentGroup.Groups[i].Name == groupName {
			return &parentGroup.Groups[i], nil
		}
	}

	return nil, fmt.Errorf("group '%s' not found", groupName)
}

// findEntryByPath finds an entry by its path within a group
// Path format: /entry or /group1/group2/entry
func findEntryByPath(envGroup *gokeepasslib.Group, entryPath string) (*gokeepasslib.Entry, error) {
	if envGroup == nil {
		return nil, fmt.Errorf("environment group is nil")
	}

	// Remove leading slash
	if len(entryPath) > 0 && entryPath[0] == '/' {
		entryPath = entryPath[1:]
	}

	if entryPath == "" {
		return nil, fmt.Errorf("entry path is empty")
	}

	// Split path into components
	components := strings.Split(entryPath, "/")
	if len(components) == 0 {
		return nil, fmt.Errorf("invalid entry path")
	}

	// Navigate through intermediate groups
	currentGroup := envGroup
	for i := 0; i < len(components)-1; i++ {
		groupName := components[i]
		if groupName == "" {
			continue
		}

		found := false
		for j := range currentGroup.Groups {
			if currentGroup.Groups[j].Name == groupName {
				currentGroup = &currentGroup.Groups[j]
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("group '%s' not found in path", groupName)
		}
	}

	// Find entry in the final group
	entryName := components[len(components)-1]
	if entryName == "" {
		return nil, fmt.Errorf("entry name is empty")
	}

	for i := range currentGroup.Entries {
		for _, value := range currentGroup.Entries[i].Values {
			if value.Key == "Title" && value.Value.Content == entryName {
				return &currentGroup.Entries[i], nil
			}
		}
	}

	return nil, fmt.Errorf("entry '%s' not found", entryName)
}

// IsStandardField checks if a field name is a standard KeePass field (case-insensitive)
// Standard fields: Title, UserName, Password, URL, Notes
func (m *manager) IsStandardField(fieldName string) bool {
	return m.profileOps.IsStandardField(fieldName)
}

// SetStandardField sets a standard KeePass field in an entry
// Field name is case-insensitive and will be normalized to standard casing
func (m *manager) SetStandardField(profileName, envName, entryPath, fieldName, value string) error {
	return m.profileOps.SetStandardField(profileName, envName, entryPath, fieldName, value)
}

// SetCustomField sets a custom field in an entry
// Field name casing is preserved exactly as provided
func (m *manager) SetCustomField(profileName, envName, entryPath, fieldName, value string) error {
	return m.profileOps.SetCustomField(profileName, envName, entryPath, fieldName, value)
}

// CreateAttachment creates an attachment in an entry
// If the attachment already exists, it does nothing (does not replace)
// Attachments in gokeepasslib use a BinaryReference system where:
// 1. Binary data is stored in db.Content.Meta.Binaries
// 2. Entry references binary by ID via entry.Binaries (BinaryReference)
func (m *manager) CreateAttachment(profileName, envName, entryPath, attachmentName string, data []byte) error {
	return m.profileOps.CreateAttachment(profileName, envName, entryPath, attachmentName, data)
}

// DeleteAttachment removes an attachment from an entry
func (m *manager) DeleteAttachment(profileName, envName, entryPath, attachmentName string) error {
	return m.profileOps.DeleteAttachment(profileName, envName, entryPath, attachmentName)
}

// FieldExists checks if a field exists in an entry (standard or custom field)
// For standard fields, comparison is case-insensitive
// For custom fields, comparison is case-sensitive
func (m *manager) FieldExists(profileName, envName, entryPath, fieldName string) (bool, error) {
	return m.profileOps.FieldExists(profileName, envName, entryPath, fieldName)
}

// GetFieldValue retrieves the value of a specific field in an entry
func (m *manager) GetFieldValue(profileName, envName, entryPath, fieldName string) (string, error) {
	return m.profileOps.GetFieldValue(profileName, envName, entryPath, fieldName)
}

func (m *manager) GetAttachmentContent(profileName, envName, entryPath, attachmentName string) ([]byte, error) {
	return m.profileOps.GetAttachmentContent(profileName, envName, entryPath, attachmentName)
}

// ListProfileTreeGroups lists all tree groups (HEAD, v1, v2, etc.) for a given profile
// Returns the list of tree group names
func (m *manager) ListProfileTreeGroups(profileName string) ([]string, error) {
	return m.snapshotOps.ListProfileTreeGroups(profileName)
}

// GetTreeGroupEntryField retrieves a field value from an entry within a tree group
// profileName: the profile name
// treeGroup: the tree group name (e.g., "HEAD", "v1", "v2")
// entryPath: path to the entry (e.g., "metadata" or "/env/path/to/entry")
// fieldName: the field name to retrieve
func (m *manager) GetTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName string) (*common.SecureValue, error) {
	return m.snapshotOps.GetTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName)
}

// CloneTreeGroup clones a source tree group to a new tree group within the same profile
// This performs a recursive deep copy of all subgroups and entries
func (m *manager) CloneTreeGroup(profileName, sourceTreeGroup, targetTreeGroup string) error {
	return m.snapshotOps.CloneTreeGroup(profileName, sourceTreeGroup, targetTreeGroup)
}

// SetTreeGroupEntryField sets a field value in an entry within a tree group
func (m *manager) SetTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName, value string) error {
	return m.snapshotOps.SetTreeGroupEntryField(profileName, treeGroup, entryPath, fieldName, value)
}

// deepCloneGroup performs a deep clone of a group and all its subgroups/entries
func deepCloneGroup(source *gokeepasslib.Group) gokeepasslib.Group {
	cloned := gokeepasslib.Group{
		UUID:                    gokeepasslib.NewUUID(),
		Name:                    source.Name,
		Notes:                   source.Notes,
		IconID:                  source.IconID,
		Times:                   source.Times,
		IsExpanded:              source.IsExpanded,
		DefaultAutoTypeSequence: source.DefaultAutoTypeSequence,
		EnableAutoType:          source.EnableAutoType,
		EnableSearching:         source.EnableSearching,
		LastTopVisibleEntry:     source.LastTopVisibleEntry,
	}

	// Clone entries
	cloned.Entries = make([]gokeepasslib.Entry, len(source.Entries))
	for i, entry := range source.Entries {
		cloned.Entries[i] = deepCloneEntry(&entry)
	}

	// Clone subgroups recursively
	cloned.Groups = make([]gokeepasslib.Group, len(source.Groups))
	for i, group := range source.Groups {
		cloned.Groups[i] = deepCloneGroup(&group)
	}

	return cloned
}

// deepCloneEntry performs a deep clone of an entry
func deepCloneEntry(source *gokeepasslib.Entry) gokeepasslib.Entry {
	cloned := gokeepasslib.Entry{
		UUID:            gokeepasslib.NewUUID(),
		IconID:          source.IconID,
		ForegroundColor: source.ForegroundColor,
		BackgroundColor: source.BackgroundColor,
		OverrideURL:     source.OverrideURL,
		Tags:            source.Tags,
		Times:           source.Times,
	}

	// Clone values
	cloned.Values = make([]gokeepasslib.ValueData, len(source.Values))
	for i, value := range source.Values {
		cloned.Values[i] = gokeepasslib.ValueData{
			Key:   value.Key,
			Value: gokeepasslib.V{Content: value.Value.Content, Protected: value.Value.Protected},
		}
	}

	// Clone binaries if any
	if len(source.Binaries) > 0 {
		cloned.Binaries = make([]gokeepasslib.BinaryReference, len(source.Binaries))
		copy(cloned.Binaries, source.Binaries)
	}

	return cloned
}

// TreeGroupExists checks if a tree group exists under a profile
func (m *manager) TreeGroupExists(profileName, treeGroup string) (bool, error) {
	return m.snapshotOps.TreeGroupExists(profileName, treeGroup)
}

// RenameTreeGroup renames a tree group under a profile
func (m *manager) RenameTreeGroup(profileName, oldName, newName string) error {
	return m.snapshotOps.RenameTreeGroup(profileName, oldName, newName)
}

// DeleteTreeGroup deletes a tree group under a profile
func (m *manager) DeleteTreeGroup(profileName, treeGroup string) error {
	return m.snapshotOps.DeleteTreeGroup(profileName, treeGroup)
}

// splitPath splits a path by "/" using cache for performance
// Returns cached result if available, otherwise splits and caches
func (m *manager) splitPath(path string) []string {
	if cached, ok := m.pathCache[path]; ok {
		return cached
	}

	parts := strings.Split(path, "/")
	m.pathCache[path] = parts
	return parts
}

// clearPathCache clears the path cache after database modifications
// Should be called after any operation that modifies the database structure
func (m *manager) clearPathCache() {
	m.pathCache = make(map[string][]string)
}
