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
	"github.com/Yohnah/secrets/internal/validator"
)

// Service defines the interface for snapshots operations
type Service interface {
	List(profileName string) error
	New(profileName string) error
}

type service struct {
	config    config.Manager
	logger    logger.Manager
	prompt    prompt.Manager
	keepass   keepass.Manager
	output    output.Manager
	validator validator.ValidatorManager
}

// NewService creates a new snapshots service instance
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
	// Step 1: Read secrets.yml and validate
	secretsFilePath := s.config.GetSecretsFilePath()
	if secretsFilePath == "" {
		return fmt.Errorf("secrets.yml file not found. Use --secrets-file flag or set SECRETS_YOHNAH_SECRETS_FILE environment variable")
	}

	secretsConfig, errs := s.validator.ReadAndValidateSecretsYML(secretsFilePath)
	if len(errs) > 0 {
		return fmt.Errorf("invalid secrets.yml: %v", errs[0])
	}

	// Step 2: Determine which profiles to list
	var profilesToList []string
	if profileName == "all" {
		for _, profile := range secretsConfig.Profiles {
			profilesToList = append(profilesToList, profile.Metadata.Profile)
		}
	} else {
		found := false
		for _, profile := range secretsConfig.Profiles {
			if profile.Metadata.Profile == profileName {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("profile '%s' not found in secrets.yml", profileName)
		}
		profilesToList = append(profilesToList, profileName)
	}

	if len(profilesToList) == 0 {
		s.logger.Info("No profiles found in secrets.yml")
		return nil
	}

	// Step 3: Get configuration and password
	cfg, err := s.config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	password, err := s.getPassword(cfg)
	if err != nil {
		return err
	}

	// Step 4: Open database
	dbPath := s.config.GetDatabasePath()
	keyfilePath := s.config.GetKeyfilePath()

	err = s.keepass.Open(dbPath, keyfilePath, password)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer s.keepass.CloseWithoutSave()

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

// getPassword retrieves password from config or prompts user
func (s *service) getPassword(cfg *config.Config) (string, error) {
	// Check if password is provided via config (from env var or other sources)
	if cfg.Password != "" {
		s.logger.Debug("Using password from configuration (SECRETS_YOHNAH_PASSWORD environment variable)")
		return cfg.Password, nil
	}

	// If in non-interactive mode and no password provided, fail
	if cfg.NoInteractive {
		return "", fmt.Errorf("password required. Set SECRETS_YOHNAH_PASSWORD environment variable or remove -f flag")
	}

	// Prompt user for password
	return s.prompt.PromptPassword("Enter database password: ")
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
	_, err := s.keepass.GetTreeGroupEntryField(profileName, treeGroup, "metadata", "version")
	if err != nil {
		return snapshot, fmt.Errorf("failed to read version: %w", err)
	}

	// For versions like v1, v2, use the tree group name as version
	// The version field in metadata is the incremental number
	snapshot.Version = treeGroup // Read datetime field from metadata entry
	datetimeStr, err := s.keepass.GetTreeGroupEntryField(profileName, treeGroup, "metadata", "datetime")
	if err != nil {
		return snapshot, fmt.Errorf("failed to read datetime: %w", err)
	}

	// Parse datetime (ISO 8601 format)
	datetime, err := time.Parse(time.RFC3339, datetimeStr)
	if err != nil {
		return snapshot, fmt.Errorf("failed to parse datetime '%s': %w", datetimeStr, err)
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
	// Step 1: Read and validate secrets.yml
	secretsFilePath := s.config.GetSecretsFilePath()
	if secretsFilePath == "" {
		return fmt.Errorf("secrets.yml file not found. Use --secrets-file flag or set SECRETS_YOHNAH_SECRETS_FILE environment variable")
	}

	secretsConfig, errs := s.validator.ReadAndValidateSecretsYML(secretsFilePath)
	if len(errs) > 0 {
		return fmt.Errorf("invalid secrets.yml: %v", errs[0])
	}

	// Step 2: Check if profile exists in secrets.yml
	profileFound := false
	for _, profile := range secretsConfig.Profiles {
		if profile.Metadata.Profile == profileName {
			profileFound = true
			break
		}
	}
	if !profileFound {
		return fmt.Errorf("error: Profile '%s' does not exist in secrets.yml. Please check your configuration", profileName)
	}

	// Step 3: Get configuration
	cfg, err := s.config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Step 3b: Ask for confirmation if not in force mode (BEFORE opening database)
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

	// Step 4: Get password
	password, err := s.getPassword(cfg)
	if err != nil {
		return err
	}

	// Step 5: Open database
	dbPath := s.config.GetDatabasePath()
	keyfilePath := s.config.GetKeyfilePath()

	err = s.keepass.Open(dbPath, keyfilePath, password)
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
	versionStr, err := s.keepass.GetTreeGroupEntryField(profileName, "HEAD", "metadata", "version")
	if err != nil {
		return fmt.Errorf("error: HEAD metadata is invalid. Failed to read version field: %w. Please check your database", err)
	}

	currentVersion, err := strconv.Atoi(versionStr)
	if err != nil {
		return fmt.Errorf("error: HEAD metadata is invalid. Version field '%s' is not a valid number: %w. Please check your database", versionStr, err)
	}

	if currentVersion < 1 {
		return fmt.Errorf("error: HEAD metadata is invalid. Version must be >= 1, found: %d. Please check your database", currentVersion)
	}

	// Step 7: Read HEAD datetime to validate it exists and is valid ISO 8601
	datetimeStr, err := s.keepass.GetTreeGroupEntryField(profileName, "HEAD", "metadata", "datetime")
	if err != nil {
		return fmt.Errorf("error: HEAD metadata is invalid. Failed to read datetime field: %w. Please check your database", err)
	}

	_, err = time.Parse(time.RFC3339, datetimeStr)
	if err != nil {
		return fmt.Errorf("error: HEAD metadata is invalid. Datetime field '%s' is not valid ISO 8601 format: %w. Please check your database", datetimeStr, err)
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
