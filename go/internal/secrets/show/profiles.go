package show

import (
	"fmt"
	"sort"

	"github.com/Yohnah/secrets/internal/secrets/common"
	"github.com/Yohnah/secrets/internal/validator"
)

// ProfileInfo represents information about a single profile
type ProfileInfo struct {
	Profile      string            `json:"profile" yaml:"profile"`
	Environments []EnvironmentInfo `json:"environments" yaml:"environments"`
	Total        int               `json:"total" yaml:"total"`
}

// EnvironmentInfo represents information about a single environment
type EnvironmentInfo struct {
	Environment  string `json:"environment" yaml:"environment"`
	ExistsInDB   bool   `json:"exists_in_db" yaml:"exists_in_db"`
	EntriesCount string `json:"entries_count" yaml:"entries_count"`
}

// Profiles displays profiles and their environments from secrets.yml
func (s *service) Profiles(profileFilter string) error {
	// Step 1: Read and validate secrets.yml
	secretsFilePath := s.config.GetSecretsFilePath()
	if secretsFilePath == "" {
		return fmt.Errorf("secrets.yml file not found. Use --secrets-file flag or set SECRETS_YOHNAH_SECRETS_FILE environment variable")
	}

	secretsConfig, errs := s.validator.ReadAndValidateSecretsYML(secretsFilePath)
	if len(errs) > 0 {
		return fmt.Errorf("invalid secrets.yml: %v", errs[0])
	}

	// Step 2: Determine which profiles to show
	var profilesToShow []validator.Profile
	if profileFilter == "all" {
		profilesToShow = secretsConfig.Profiles
	} else {
		found := false
		for _, profile := range secretsConfig.Profiles {
			if profile.Metadata.Profile == profileFilter {
				profilesToShow = append(profilesToShow, profile)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("profile '%s' not found in secrets.yml", profileFilter)
		}
	}

	if len(profilesToShow) == 0 {
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

	// Step 5: For each profile, gather information
	var allProfiles []ProfileInfo

	for _, profile := range profilesToShow {
		profileName := profile.Metadata.Profile

		// Check if profile exists in database
		profileExistsInDB, err := s.keepass.ProfileExists(profileName)
		if err != nil {
			s.logger.Error(fmt.Sprintf("Error checking profile '%s': %v", profileName, err))
			continue
		}

		// Get environments
		var environments []EnvironmentInfo
		for envName := range profile.Environments {
			envInfo := EnvironmentInfo{
				Environment:  envName,
				ExistsInDB:   false,
				EntriesCount: "0/0 entries",
			}

			// If profile exists in DB, check environment and count entries
			if profileExistsInDB {
				// Try to get entries from environment to see if it exists
				dbEntries, err := s.keepass.GetEntriesByEnvironment(profileName, envName)
				if err != nil {
					s.logger.Error(fmt.Sprintf("Error getting entries for %s/%s: %v", profileName, envName, err))
					totalEntries := len(profile.Environments[envName])
					envInfo.EntriesCount = fmt.Sprintf("0/%d entries", totalEntries)
				} else {
					// If we got entries (even if empty), the environment exists
					// We need to check if HEAD group exists by trying to get entries
					// An environment exists if GetEntriesByEnvironment returns without error

					// Count existing entries
					totalEntries := len(profile.Environments[envName])
					existingEntries := s.countExistingEntries(profile.Environments[envName], dbEntries)

					// Determine if environment exists: it exists if we got entries back or if total > 0
					envInfo.ExistsInDB = len(dbEntries) > 0 || existingEntries > 0
					envInfo.EntriesCount = fmt.Sprintf("%d/%d entries", existingEntries, totalEntries)
				}
			} else {
				// Profile not in database
				totalEntries := len(profile.Environments[envName])
				envInfo.EntriesCount = fmt.Sprintf("0/%d entries", totalEntries)
			}

			environments = append(environments, envInfo)
		}

		// Sort environments alphabetically
		sort.Slice(environments, func(i, j int) bool {
			return environments[i].Environment < environments[j].Environment
		})

		allProfiles = append(allProfiles, ProfileInfo{
			Profile:      profileName,
			Environments: environments,
			Total:        len(environments),
		})
	}

	// Sort profiles alphabetically
	sort.Slice(allProfiles, func(i, j int) bool {
		return allProfiles[i].Profile < allProfiles[j].Profile
	})

	// Step 6: Output results
	outputFormat := cfg.OutputFormat
	if outputFormat == "" {
		outputFormat = "table"
	}

	// Structure data with _display metadata for OutputManager
	structuredData := s.structureProfilesData(allProfiles)

	return s.output.Output(structuredData, outputFormat)
}

// countExistingEntries counts how many entries from secrets.yml exist in the DB
func (s *service) countExistingEntries(items []validator.Item, dbEntries []string) int {
	// Create a map of DB entries for quick lookup
	dbEntriesMap := make(map[string]bool)
	for _, entry := range dbEntries {
		dbEntriesMap[entry] = true
	}

	// Count matching entries
	existingEntries := 0
	for _, item := range items {
		// The entry path in secrets.yml has format: /EnvironmentName/path/to/entry
		// But in DB it's stored as: path/to/entry
		// So we need to extract the relative path

		// Find first / after the environment prefix
		path := item.Entry
		if len(path) > 0 && path[0] == '/' {
			// Skip the leading /
			path = path[1:]
			// Find the next / (end of environment name)
			slashIndex := -1
			for i, ch := range path {
				if ch == '/' {
					slashIndex = i
					break
				}
			}
			if slashIndex >= 0 && slashIndex < len(path)-1 {
				// Extract path after environment name
				relativePath := path[slashIndex+1:]
				if dbEntriesMap[relativePath] {
					existingEntries++
				}
			}
		}
	}

	return existingEntries
}

// structureProfilesData structures profiles data with _display metadata for OutputManager
func (s *service) structureProfilesData(profiles []ProfileInfo) map[string]interface{} {
	result := make(map[string]interface{})

	// Add display metadata
	result["_display"] = map[string]interface{}{
		"title":  "Profiles",
		"format": "profiles_list",
	}

	// Structure profiles data
	profilesData := make([]map[string]interface{}, 0, len(profiles))
	for _, profile := range profiles {
		profileData := map[string]interface{}{
			"name":  profile.Profile,
			"total": profile.Total,
		}

		// Structure environments for this profile
		environmentsData := make([]map[string]interface{}, 0, len(profile.Environments))
		for _, env := range profile.Environments {
			envData := map[string]interface{}{
				"name":          env.Environment,
				"exists_in_db":  env.ExistsInDB,
				"entries_count": env.EntriesCount,
			}
			environmentsData = append(environmentsData, envData)
		}

		profileData["environments"] = environmentsData
		profilesData = append(profilesData, profileData)
	}

	result["profiles"] = profilesData

	return result
}
