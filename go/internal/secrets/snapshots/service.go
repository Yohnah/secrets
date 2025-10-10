package snapshots

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/output"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets/common"
	"github.com/Yohnah/secrets/internal/secrets/profile"
	"github.com/Yohnah/secrets/internal/validator"
)

// Service defines the interface for snapshots operations
type Service interface {
	List(profileName string) error
	New(profileName string) error
	Restore(profileName, version string) error
	Delete(profileName, version string) error
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

// NewService creates a new snapshots service instance
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

// SnapshotInfo represents information about a single snapshot
type SnapshotInfo struct {
	Profile   string    `json:"profile" yaml:"profile"`
	Version   string    `json:"version" yaml:"version"`
	IsActive  bool      `json:"is_active" yaml:"is_active"`
	DateTime  time.Time `json:"datetime" yaml:"datetime"`
	Age       string    `json:"age" yaml:"age"`
	IsMutable bool      `json:"is_mutable" yaml:"is_mutable"`
}

// ProfileSnapshots represents all snapshots for a single profile
type ProfileSnapshots struct {
	Profile   string         `json:"profile" yaml:"profile"`
	Snapshots []SnapshotInfo `json:"snapshots" yaml:"snapshots"`
	Total     int            `json:"total" yaml:"total"`
}

// List lists snapshots for a specific profile or all profiles
func (s *service) List(profileName string) error {
	// Step 1: Determine profiles to list using resolver
	var profilesToList []string

	if profileName == "all" {
		config, err := s.profileResolver.LoadConfig()
		if err != nil {
			return err
		}

		for _, profile := range config.Profiles {
			profilesToList = append(profilesToList, profile.Metadata.Profile)
		}
	} else {
		resolvedProfile, err := s.profileResolver.Resolve(profileName)
		if err != nil {
			return err
		}

		profilesToList = append(profilesToList, resolvedProfile.Name)
	}

	if len(profilesToList) == 0 {
		s.logger.Info("No profiles found in secrets.yml")
		return nil
	}

	// Step 3: Get configuration
	cfg, err := s.config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Step 4: Get password (secure)
	securePassword, err := common.GetPassword(s.config, s.prompt, s.logger, false)
	if err != nil {
		return err
	}
	defer securePassword.Clear() // Ensure password is cleared from memory

	// Step 5: Open database
	dbPath := s.config.GetDatabasePath()
	keyfilePath := s.config.GetKeyfilePath()

	err = s.keepass.Open(dbPath, keyfilePath, securePassword.String())
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer s.keepass.CloseWithoutSave()

	// Validate database integrity
	if errs := s.validator.ValidateKeePassDuplicates(s.keepass); len(errs) > 0 {
		return fmt.Errorf("database corruption detected: %v", errs[0])
	}

	// Step 5: For each profile, read snapshots from database
	var allSnapshots []ProfileSnapshots

	for _, profile := range profilesToList {
		// Check if profile exists in database
		exists, err := s.keepass.ProfileExists(profile)
		if err != nil {
			s.logger.Error(fmt.Sprintf("Error checking profile '%s': %v", profile, err))
			continue
		}
		if !exists {
			s.logger.Info(fmt.Sprintf("Profile '%s' not found in database, skipping", profile))
			continue
		}

		// List tree groups (HEAD, v1, v2, etc.)
		treeGroups, err := s.keepass.ListProfileTreeGroups(profile)
		if err != nil {
			s.logger.Error(fmt.Sprintf("Error listing tree groups for profile '%s': %v", profile, err))
			continue
		}

		// Read metadata for each tree group
		var snapshots []SnapshotInfo
		for _, treeGroup := range treeGroups {
			snapshot, err := s.readSnapshotMetadata(profile, treeGroup)
			if err != nil {
				s.logger.Error(fmt.Sprintf("Error reading metadata for %s/%s: %v", profile, treeGroup, err))
				continue
			}
			snapshots = append(snapshots, snapshot)
		}

		// Sort snapshots: HEAD first, then v1, v2, v3...
		sort.Slice(snapshots, func(i, j int) bool {
			if snapshots[i].Version == "HEAD" {
				return true
			}
			if snapshots[j].Version == "HEAD" {
				return false
			}
			// Extract version numbers for sorting
			vi := extractVersionNumber(snapshots[i].Version)
			vj := extractVersionNumber(snapshots[j].Version)
			return vi < vj
		})

		allSnapshots = append(allSnapshots, ProfileSnapshots{
			Profile:   profile,
			Snapshots: snapshots,
			Total:     len(snapshots),
		})
	}

	// Step 6: Output results with the correct format from config
	outputFormat := cfg.OutputFormat
	if outputFormat == "" {
		outputFormat = "table"
	}

	// Structure data with _display metadata for OutputManager
	structuredData := s.structureSnapshotsData(allSnapshots)

	return s.output.Output(structuredData, outputFormat)
}

// readSnapshotMetadata reads metadata from a tree group
func (s *service) readSnapshotMetadata(profileName, treeGroup string) (SnapshotInfo, error) {
	snapshot := SnapshotInfo{
		Profile:   profileName,
		Version:   treeGroup,
		IsActive:  treeGroup == "HEAD",
		IsMutable: treeGroup == "HEAD",
	}

	// Read version field from metadata entry
	versionSecure, err := s.keepass.GetTreeGroupEntryField(profileName, treeGroup, "metadata", "version")
	if err != nil {
		return snapshot, fmt.Errorf("failed to read version: %w", err)
	}
	defer versionSecure.Clear()

	// For versions like v1, v2, use the tree group name as version
	// The version field in metadata is the incremental number
	snapshot.Version = treeGroup // Read datetime field from metadata entry
	datetimeSecure, err := s.keepass.GetTreeGroupEntryField(profileName, treeGroup, "metadata", "datetime")
	if err != nil {
		return snapshot, fmt.Errorf("failed to read datetime: %w", err)
	}
	defer datetimeSecure.Clear()

	// Parse datetime (ISO 8601 format)
	var datetime time.Time
	if datetimeSecure.String() == "" {
		// Fallback to current time if datetime is empty (for backward compatibility)
		datetime = time.Now().UTC()
	} else {
		datetime, err = time.Parse(time.RFC3339, datetimeSecure.String())
		if err != nil {
			return snapshot, fmt.Errorf("failed to parse datetime field: invalid ISO 8601 format: %w", err)
		}
	}
	snapshot.DateTime = datetime

	// Calculate age
	snapshot.Age = calculateAge(datetime)

	return snapshot, nil
}

// calculateAge returns a human-friendly age string
func calculateAge(t time.Time) string {
	duration := time.Since(t)

	days := int(duration.Hours() / 24)
	if days > 0 {
		return fmt.Sprintf("%dd", days)
	}

	hours := int(duration.Hours())
	if hours > 0 {
		return fmt.Sprintf("%dh", hours)
	}

	minutes := int(duration.Minutes())
	if minutes > 0 {
		return fmt.Sprintf("%dm", minutes)
	}

	return "just now"
}

// extractVersionNumber extracts the numeric part from version string (e.g., "v2" -> 2)
func extractVersionNumber(version string) int {
	if strings.HasPrefix(version, "v") {
		numStr := version[1:]
		num, err := strconv.Atoi(numStr)
		if err != nil {
			return 0
		}
		return num
	}
	return 0
}

// structureSnapshotsData structures snapshots data with _display metadata for OutputManager
func (s *service) structureSnapshotsData(profiles []ProfileSnapshots) map[string]interface{} {
	result := make(map[string]interface{})

	// Add display metadata
	result["_display"] = map[string]interface{}{
		"title":  "Snapshots",
		"format": "snapshots_list",
	}

	// Structure profiles data
	profilesData := make([]map[string]interface{}, 0, len(profiles))
	for _, profile := range profiles {
		profileData := map[string]interface{}{
			"name":  profile.Profile,
			"total": profile.Total,
		}

		// Structure snapshots for this profile
		snapshotsData := make([]map[string]interface{}, 0, len(profile.Snapshots))
		for _, snapshot := range profile.Snapshots {
			snapshotData := map[string]interface{}{
				"version":    snapshot.Version,
				"is_active":  snapshot.IsActive,
				"datetime":   snapshot.DateTime.Format(time.RFC3339),
				"age":        snapshot.Age,
				"is_mutable": snapshot.IsMutable,
			}
			snapshotsData = append(snapshotsData, snapshotData)
		}

		profileData["snapshots"] = snapshotsData
		profilesData = append(profilesData, profileData)
	}

	result["profiles"] = profilesData

	return result
}

// New creates a new snapshot by cloning HEAD to v{current_version} and incrementing HEAD version
func (s *service) New(profileName string) error {
	// Step 1: Resolve profile (auto-detect when possible)
	resolvedProfile, err := s.profileResolver.Resolve(profileName)
	if err != nil {
		return err
	}
	profileName = resolvedProfile.Name

	// Step 2: Get configuration
	cfg, err := s.config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Step 3: Ask for confirmation if not in force mode (BEFORE opening database)
	if !cfg.NoInteractive {
		s.logger.Info(fmt.Sprintf("You are about to create a new snapshot for profile '%s'.", profileName))
		s.logger.Info("This will clone HEAD to a new versioned snapshot and update the database.")
		confirmed, err := s.prompt.Confirm("Do you want to continue?")
		if err != nil {
			return fmt.Errorf("failed to get confirmation: %w", err)
		}
		if !confirmed {
			s.logger.Info("Operation cancelled by user")
			return nil
		}
	}

	// Step 4: Get password (secure)
	securePassword, err := common.GetPassword(s.config, s.prompt, s.logger, false)
	if err != nil {
		return err
	}
	defer securePassword.Clear() // Ensure password is cleared from memory

	// Step 5: Open database
	dbPath := s.config.GetDatabasePath()
	keyfilePath := s.config.GetKeyfilePath()

	err = s.keepass.Open(dbPath, keyfilePath, securePassword.String())
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer s.keepass.SaveAndClose() // Use SaveAndClose() to save changes

	// Step 6: Check if profile exists in database
	profileExistsInDB, err := s.keepass.ProfileExists(profileName)
	if err != nil {
		return fmt.Errorf("error checking profile in database: %w", err)
	}
	if !profileExistsInDB {
		return fmt.Errorf("error: Profile '%s' does not exist in database. Please check your configuration", profileName)
	}

	// Step 7: Read HEAD metadata to get current version
	versionSecure, err := s.keepass.GetTreeGroupEntryField(profileName, "HEAD", "metadata", "version")
	if err != nil {
		return fmt.Errorf("error: HEAD metadata is invalid. Failed to read version field: %w. Please check your database", err)
	}
	defer versionSecure.Clear()

	currentVersion, err := strconv.Atoi(versionSecure.String())
	if err != nil {
		return fmt.Errorf("error: HEAD metadata is invalid. Version field is not a valid number: %w. Please check your database", err)
	}

	if currentVersion < 1 {
		return fmt.Errorf("error: HEAD metadata is invalid. Version must be >= 1, found: %d. Please check your database", currentVersion)
	}

	// Step 7: Read HEAD datetime to validate it exists and is valid ISO 8601
	datetimeSecure, err := s.keepass.GetTreeGroupEntryField(profileName, "HEAD", "metadata", "datetime")
	if err != nil {
		return fmt.Errorf("error: HEAD metadata is invalid. Failed to read datetime field: %w. Please check your database", err)
	}
	defer datetimeSecure.Clear()

	_, err = time.Parse(time.RFC3339, datetimeSecure.String())
	if err != nil {
		return fmt.Errorf("error: HEAD metadata is invalid. Datetime field is not valid ISO 8601 format: %w. Please check your database", err)
	}

	// Step 8: Check if v{currentVersion} already exists (should not happen, but validate)
	newSnapshotName := fmt.Sprintf("v%d", currentVersion)
	treeGroups, err := s.keepass.ListProfileTreeGroups(profileName)
	if err != nil {
		return fmt.Errorf("failed to list tree groups for profile '%s': %w", profileName, err)
	}

	for _, treeGroup := range treeGroups {
		if treeGroup == newSnapshotName {
			return fmt.Errorf("error: Snapshot '%s' already exists for profile '%s'. Database may be corrupted. Please check your database", newSnapshotName, profileName)
		}
	}

	// Step 9: Clone HEAD to v{currentVersion}
	s.logger.Info(fmt.Sprintf("Creating snapshot '%s' for profile '%s'...", newSnapshotName, profileName))
	err = s.keepass.CloneTreeGroup(profileName, "HEAD", newSnapshotName)
	if err != nil {
		return fmt.Errorf("failed to clone HEAD to %s: %w", newSnapshotName, err)
	}

	// Step 10: Update datetime in v{currentVersion} metadata to current moment
	// (ISO 8601 format: 2025-10-08T14:57:43Z)
	snapshotDatetime := time.Now().UTC().Format(time.RFC3339)
	err = s.keepass.SetTreeGroupEntryField(profileName, newSnapshotName, "metadata", "datetime", snapshotDatetime)
	if err != nil {
		return fmt.Errorf("failed to update %s datetime: %w", newSnapshotName, err)
	}

	// Step 11: Increment version in HEAD metadata (datetime remains unchanged)
	newVersion := currentVersion + 1
	newVersionStr := strconv.Itoa(newVersion)
	err = s.keepass.SetTreeGroupEntryField(profileName, "HEAD", "metadata", "version", newVersionStr)
	if err != nil {
		return fmt.Errorf("failed to update HEAD version: %w", err)
	}

	// Step 12: Success message
	s.logger.Info(fmt.Sprintf("Snapshot '%s' created successfully for profile '%s'", newSnapshotName, profileName))
	s.logger.Info(fmt.Sprintf("HEAD updated to version %d", newVersion))

	return nil
}

// Restore restores a snapshot to HEAD
// This method renames current HEAD to v{currentVersion}, then clones specified version to new HEAD
func (s *service) Restore(profileName, version string) error {
	// Step 1: Resolve profile (auto-detect when possible)
	resolvedProfile, err := s.profileResolver.Resolve(profileName)
	if err != nil {
		return err
	}
	profileName = resolvedProfile.Name

	// Step 2: Get configuration
	cfg, err := s.config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Step 3: Ask for confirmation if not in force mode (BEFORE opening database)
	if !cfg.NoInteractive {
		s.logger.Info(fmt.Sprintf("You are about to restore snapshot '%s' for profile '%s'.", version, profileName))
		s.logger.Info("This will rename current HEAD to a new version and restore the specified snapshot as new HEAD.")
		confirmed, err := s.prompt.Confirm("Do you want to continue?")
		if err != nil {
			return fmt.Errorf("failed to get confirmation: %w", err)
		}
		if !confirmed {
			s.logger.Info("Operation cancelled by user")
			return nil
		}
	}

	// Step 4: Get password (secure)
	securePassword, err := common.GetPassword(s.config, s.prompt, s.logger, false)
	if err != nil {
		return err
	}
	defer securePassword.Clear() // Ensure password is cleared from memory

	// Step 5: Open database
	dbPath := s.config.GetDatabasePath()
	keyfilePath := s.config.GetKeyfilePath()

	err = s.keepass.Open(dbPath, keyfilePath, securePassword.String())
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer s.keepass.SaveAndClose() // Use SaveAndClose() to save changes

	// Step 6: Check if profile exists in database
	profileExistsInDB, err := s.keepass.ProfileExists(profileName)
	if err != nil {
		return fmt.Errorf("error checking profile in database: %w", err)
	}
	if !profileExistsInDB {
		return fmt.Errorf("error: Profile '%s' does not exist in database. Please check your configuration", profileName)
	}

	// Step 7: Validate target snapshot exists
	targetExists, err := s.keepass.TreeGroupExists(profileName, version)
	if err != nil {
		return fmt.Errorf("error checking if snapshot '%s' exists: %w", version, err)
	}
	if !targetExists {
		return fmt.Errorf("error: Snapshot '%s' does not exist for profile '%s'. Please check available snapshots", version, profileName)
	}

	// Step 8: Read current HEAD version from metadata
	currentVersionSecure, err := s.keepass.GetTreeGroupEntryField(profileName, "HEAD", "metadata", "version")
	if err != nil {
		return fmt.Errorf("error: HEAD metadata is invalid. Failed to read version field: %w. Please check your database", err)
	}
	defer currentVersionSecure.Clear()

	// Convert version string to integer
	currentVersion, err := strconv.Atoi(currentVersionSecure.String())
	if err != nil {
		return fmt.Errorf("error: HEAD metadata version is invalid (not a number): %w. Please check your database", err)
	}

	// Step 9: Rename current HEAD to v{currentVersion}
	oldHeadName := fmt.Sprintf("v%d", currentVersion)
	s.logger.Info(fmt.Sprintf("Renaming current HEAD to '%s'...", oldHeadName))
	err = s.keepass.RenameTreeGroup(profileName, "HEAD", oldHeadName)
	if err != nil {
		return fmt.Errorf("failed to rename HEAD to %s: %w", oldHeadName, err)
	}

	// Step 10: Update datetime in renamed HEAD (now v{currentVersion})
	// Version field NOT touched (remains currentVersion)
	oldHeadDatetime := time.Now().UTC().Format(time.RFC3339)
	err = s.keepass.SetTreeGroupEntryField(profileName, oldHeadName, "metadata", "datetime", oldHeadDatetime)
	if err != nil {
		return fmt.Errorf("failed to update %s datetime: %w", oldHeadName, err)
	}

	// Step 11: Clone target version to new HEAD
	s.logger.Info(fmt.Sprintf("Restoring snapshot '%s' to HEAD...", version))
	err = s.keepass.CloneTreeGroup(profileName, version, "HEAD")
	if err != nil {
		return fmt.Errorf("failed to clone %s to HEAD: %w", version, err)
	}

	// Step 12: Calculate new HEAD version (currentVersion + 1)
	newHeadVersion := currentVersion + 1
	newHeadVersionStr := strconv.Itoa(newHeadVersion)

	// Step 13: Update version in new HEAD metadata
	err = s.keepass.SetTreeGroupEntryField(profileName, "HEAD", "metadata", "version", newHeadVersionStr)
	if err != nil {
		return fmt.Errorf("failed to update new HEAD version: %w", err)
	}

	// Step 14: Update datetime in new HEAD metadata
	newHeadDatetime := time.Now().UTC().Format(time.RFC3339)
	err = s.keepass.SetTreeGroupEntryField(profileName, "HEAD", "metadata", "datetime", newHeadDatetime)
	if err != nil {
		return fmt.Errorf("failed to update new HEAD datetime: %w", err)
	}

	// Step 15: Success message
	s.logger.Info(fmt.Sprintf("Snapshot '%s' restored successfully to HEAD", version))
	s.logger.Info(fmt.Sprintf("Old HEAD (v%d) preserved as %s", currentVersion, oldHeadName))
	s.logger.Info(fmt.Sprintf("New HEAD version: v%d", newHeadVersion))

	return nil
}

// Delete deletes a specific snapshot version from a profile
// HEAD cannot be deleted
func (s *service) Delete(profileName, version string) error {
	// Step 1: Validate that version is not HEAD (check first before format validation)
	if strings.ToUpper(version) == "HEAD" {
		return fmt.Errorf("error: HEAD cannot be deleted. Only versioned snapshots (v1, v2, etc.) can be deleted")
	}

	// Step 2: Validate version format (must be v<number>)
	if !strings.HasPrefix(version, "v") {
		return fmt.Errorf("invalid version format: '%s'. Version must start with 'v' (e.g., v1, v2)", version)
	}

	// Extract version number
	versionNum := extractVersionNumber(version)
	if versionNum <= 0 {
		return fmt.Errorf("invalid version format: '%s'. Version must be v followed by a positive number (e.g., v1, v2)", version)
	}

	// Step 3: Resolve profile (auto-detect when possible)
	resolvedProfile, err := s.profileResolver.Resolve(profileName)
	if err != nil {
		return err
	}
	profileName = resolvedProfile.Name

	// Step 4: Get configuration
	cfg, err := s.config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Step 5: Ask for confirmation if not in force mode (BEFORE opening database)
	if !cfg.NoInteractive {
		s.logger.Info(fmt.Sprintf("You are about to DELETE snapshot '%s' from profile '%s'.", version, profileName))
		s.logger.Info("This operation is PERMANENT and cannot be undone.")
		confirmed, err := s.prompt.Confirm("Are you sure you want to continue?")
		if err != nil {
			return fmt.Errorf("failed to get confirmation: %w", err)
		}
		if !confirmed {
			s.logger.Info("Operation cancelled by user")
			return nil
		}
	}

	// Step 6: Get password (secure)
	securePassword, err := common.GetPassword(s.config, s.prompt, s.logger, false)
	if err != nil {
		return err
	}
	defer securePassword.Clear() // Ensure password is cleared from memory

	// Step 7: Open database
	dbPath := s.config.GetDatabasePath()
	keyfilePath := s.config.GetKeyfilePath()

	err = s.keepass.Open(dbPath, keyfilePath, securePassword.String())
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer s.keepass.SaveAndClose() // Use SaveAndClose() to save changes

	// Step 8: Check if profile exists in database
	profileExistsInDB, err := s.keepass.ProfileExists(profileName)
	if err != nil {
		return fmt.Errorf("error checking profile in database: %w", err)
	}
	if !profileExistsInDB {
		return fmt.Errorf("error: Profile '%s' does not exist in database. Please check your configuration", profileName)
	}

	// Step 9: Check if version exists
	versionExists, err := s.keepass.TreeGroupExists(profileName, version)
	if err != nil {
		return fmt.Errorf("error checking version in database: %w", err)
	}
	if !versionExists {
		return fmt.Errorf("error: Version '%s' not found in profile '%s'", version, profileName)
	}

	// Step 10: Delete the version group
	s.logger.Info(fmt.Sprintf("Deleting snapshot '%s' from profile '%s'...", version, profileName))
	err = s.keepass.DeleteTreeGroup(profileName, version)
	if err != nil {
		return fmt.Errorf("failed to delete version '%s': %w", version, err)
	}

	// Step 11: Success message
	s.logger.Info(fmt.Sprintf("Snapshot '%s' deleted successfully from profile '%s'", version, profileName))

	return nil
}
