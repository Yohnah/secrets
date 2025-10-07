package show

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Yohnah/secrets/internal/secrets/common"
	"github.com/tobischo/gokeepasslib/v3"
)

// Default database name when git repository name cannot be determined
const defaultDatabaseName = "SECRETS YOHNAH"

// Status displays the current status of the secrets database
func (s *service) Status(format string) error {
	s.logger.Debug("Checking database status...")

	// Get configuration
	cfg, err := s.config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Get database and keyfile paths
	dbPath := common.MakeAbsolutePath(s.config.GetDatabasePath())
	keyfilePath := common.MakeAbsolutePath(s.config.GetKeyfilePath())

	// Database name will be read from DB root group (if accessible)
	var databaseName string

	// Check if config.yml exists (unless --ignore-config-file is active)
	var configExists bool
	var configPath string
	if !s.config.ShouldIgnoreConfigFile() {
		configPath = filepath.Join(filepath.Dir(dbPath), "config.yml")
		if _, err := os.Stat(configPath); err == nil {
			configExists = true
		}
	}

	// Check if database exists
	dbInfo, dbErr := os.Stat(dbPath)
	dbExists := dbErr == nil

	// Check if keyfile exists
	keyfileInfo, keyfileErr := os.Stat(keyfilePath)
	keyfileExists := keyfileErr == nil

	// Try to open database to verify accessibility
	var accessible bool
	var accessError string
	var db *gokeepasslib.Database // Keep reference for validation later
	if dbExists && keyfileExists {
		password := cfg.Password
		if password == "" {
			if cfg.NoInteractive {
				accessError = "password required (use SECRETS_YOHNAH_PASSWORD environment variable)"
			} else {
				// Ask for password
				pwd, err := s.prompt.PromptPassword("Enter database password: ")
				if err != nil {
					accessError = fmt.Sprintf("failed to get password: %v", err)
				} else {
					password = pwd
				}
			}
		}

		if password != "" {
			s.logger.Debug("Attempting to open database...")
			openedDB, err := s.keepass.OpenDatabase(dbPath, keyfilePath, password)
			if err != nil {
				accessError = fmt.Sprintf("cannot access database: %v", err)
				accessible = false
			} else {
				accessible = true
				db = openedDB // Save database reference for validation
				s.logger.Debug("Database opened successfully")
				// Read database name from root group (first group in root)
				if len(db.Content.Root.Groups) > 0 {
					databaseName = db.Content.Root.Groups[0].Name
				} else {
					databaseName = defaultDatabaseName // Fallback if no groups
				}
			}
		}
	} else {
		accessible = false
		if !dbExists {
			accessError = "database file not found"
		} else if !keyfileExists {
			accessError = "keyfile not found"
		}
	}

	// Build structured status data with display metadata
	statusData := make(map[string]interface{})

	// Top-level display metadata
	statusData["_display"] = map[string]interface{}{
		"type":            "status_report",
		"title":           "Secrets Database Status",
		"title_separator": "=",
		"section_spacing": true,
	}

	// Configuration section (only if not ignored)
	if !s.config.ShouldIgnoreConfigFile() {
		configData := map[string]interface{}{
			"_display": map[string]interface{}{
				"label": "Configuration",
				"fields": []map[string]interface{}{
					{
						"key":    "config_file",
						"label":  "Config file",
						"format": "path_with_status",
					},
				},
			},
			"config_file": configPath,
			"exists":      configExists,
		}
		statusData["configuration"] = configData
	}

	// Secrets file section
	secretsYMLPath := s.config.GetSecretsFilePath()
	var secretsYMLExists bool
	var secretsYMLInfo os.FileInfo
	var secretsProfileCount int
	var profileNames []string

	if secretsYMLPath != "" {
		// Make path absolute for display
		secretsYMLPath = common.MakeAbsolutePath(secretsYMLPath)

		// Check if file exists
		info, err := os.Stat(secretsYMLPath)
		if err == nil {
			secretsYMLExists = true
			secretsYMLInfo = info

			// Read and parse ONCE to get all needed information
			config, _ := s.validator.ReadAndValidateSecretsYML(secretsYMLPath)
			if config != nil {
				secretsProfileCount = len(config.Profiles)
				// Extract profile names for later use
				for _, profile := range config.Profiles {
					profileNames = append(profileNames, profile.Metadata.Profile)
				}
			}
		}
	}

	secretsFileData := map[string]interface{}{
		"_display": map[string]interface{}{
			"label": "Secrets File",
			"fields": []map[string]interface{}{
				{"key": "location", "label": "Location", "format": "path_with_status"},
				{"key": "size_human", "label": "Size", "format": "simple", "condition": "exists"},
				{"key": "profiles", "label": "Profiles", "format": "simple", "condition": "exists"},
			},
			"not_found_message": "Run 'secrets show template > secrets.yml' to create a template.",
		},
		"location": secretsYMLPath,
		"exists":   secretsYMLExists,
	}
	if secretsYMLExists {
		secretsFileData["size_bytes"] = secretsYMLInfo.Size()
		secretsFileData["size_human"] = formatFileSize(secretsYMLInfo.Size())
		secretsFileData["profiles"] = secretsProfileCount
	}
	statusData["secrets_file"] = secretsFileData

	// Database section
	dbData := map[string]interface{}{
		"_display": map[string]interface{}{
			"label": "Database",
			"fields": []map[string]interface{}{
				{"key": "location", "label": "Location", "format": "path_with_status"},
				{"key": "size_human", "label": "Size", "format": "simple", "condition": "exists"},
				{"key": "modified", "label": "Modified", "format": "simple", "condition": "exists"},
				{"key": "accessible", "label": "Accessible", "format": "accessible_status", "condition": "exists"},
				{"key": "database_name", "label": "Database Name", "format": "simple", "condition": "accessible"},
				{"key": "profiles_in_secrets_file", "label": "Profiles in secrets.yml", "format": "simple", "condition": "accessible"},
				{"key": "profiles_in_database", "label": "Profiles in database", "format": "simple", "condition": "accessible"},
			},
			"not_found_message": "Run 'secrets init' to create the database.",
		},
		"location":      dbPath,
		"exists":        dbExists,
		"database_name": databaseName,
	}
	if dbExists {
		dbData["size_bytes"] = dbInfo.Size()
		dbData["size_human"] = formatFileSize(dbInfo.Size())
		dbData["modified"] = dbInfo.ModTime().Format("2006-01-02 15:04:05")
		dbData["accessible"] = accessible

		// Use profile count from secrets.yml section
		dbData["profiles_in_secrets_file"] = secretsProfileCount

		// Count profiles from secrets.yml that exist in database
		profilesInDatabase := 0
		if db != nil && len(db.Content.Root.Groups) > 0 && len(profileNames) > 0 {
			profilesInDatabase = countProfilesFromYAMLInDatabase(db.Content.Root.Groups[0].Groups, profileNames)
			s.logger.Debug(fmt.Sprintf("Database has %d profiles from secrets.yml", profilesInDatabase))
		}
		dbData["profiles_in_database"] = profilesInDatabase

		dbData["accessible_message"] = "password verified"
		if !accessible {
			dbData["accessible_message"] = accessError
		}
	}
	statusData["database"] = dbData

	// Keyfile section
	keyfileData := map[string]interface{}{
		"_display": map[string]interface{}{
			"label": "Keyfile",
			"fields": []map[string]interface{}{
				{"key": "location", "label": "Location", "format": "path_with_status"},
				{"key": "modified", "label": "Modified", "format": "simple", "condition": "exists"},
			},
			"not_found_message": "Run 'secrets init' to create the keyfile.",
		},
		"location": keyfilePath,
		"exists":   keyfileExists,
	}
	if keyfileExists {
		keyfileData["modified"] = keyfileInfo.ModTime().Format("2006-01-02 15:04:05")
	}
	statusData["keyfile"] = keyfileData

	// Pass structured data + format to OutputManager
	if err := s.output.Output(statusData, format); err != nil {
		return fmt.Errorf("failed to output status: %w", err)
	}

	// Return error if database is not accessible
	if !accessible && dbExists {
		return fmt.Errorf("database is not accessible: %s", accessError)
	}

	return nil
}

// formatFileSize formats a file size in bytes to a human-readable string
func formatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// countValidProfiles counts groups that are valid profiles (have HEAD -> metadata structure)
// A valid profile must have:
// - A subgroup named "HEAD"
// - Inside HEAD, an entry named "metadata"
func countValidProfiles(groups []gokeepasslib.Group) int {
	count := 0
	for _, group := range groups {
		// Check if this group has a HEAD subgroup
		hasHEAD := false
		for _, subgroup := range group.Groups {
			if subgroup.Name == "HEAD" {
				// Check if HEAD has a metadata entry
				for _, entry := range subgroup.Entries {
					// Get entry title
					title := ""
					for _, value := range entry.Values {
						if value.Key == "Title" {
							title = value.Value.Content
							break
						}
					}
					if title == "metadata" {
						hasHEAD = true
						break
					}
				}
				break
			}
		}
		if hasHEAD {
			count++
		}
	}
	return count
}

// countProfilesFromYAMLInDatabase counts how many profiles from secrets.yml exist in the database
// Only profiles defined in secrets.yml are counted, even if the database has other groups
func countProfilesFromYAMLInDatabase(groups []gokeepasslib.Group, profileNames []string) int {
	count := 0
	for _, profileName := range profileNames {
		// Search for this profile name in database groups
		for _, group := range groups {
			if group.Name == profileName {
				// Verify it has valid profile structure (HEAD -> metadata)
				hasValidStructure := false
				for _, subgroup := range group.Groups {
					if subgroup.Name == "HEAD" {
						// Check if HEAD has a metadata entry
						for _, entry := range subgroup.Entries {
							title := ""
							for _, value := range entry.Values {
								if value.Key == "Title" {
									title = value.Value.Content
									break
								}
							}
							if title == "metadata" {
								hasValidStructure = true
								break
							}
						}
						break
					}
				}
				if hasValidStructure {
					count++
				}
				break // Found the profile, no need to check other groups
			}
		}
	}
	return count
}
