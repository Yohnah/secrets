package show

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Yohnah/secrets/internal/keepass"
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
	var entriesCount int
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
				// Count entries
				entriesCount = countEntries(db.Content.Root.Groups)
				s.logger.Debug(fmt.Sprintf("Database has %d entries", entriesCount))
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
				{"key": "entries_count", "label": "Entries Count", "format": "simple", "condition": "accessible"},
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
		dbData["entries_count"] = entriesCount
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

	// VALIDATION SECTION: Check secrets.yml and database compliance
	s.logger.Debug("Running validation checks...")

	var allErrors []error
	validationData := make(map[string]interface{})

	// Validation display metadata
	validationData["_display"] = map[string]interface{}{
		"label": "Validation",
		"fields": []map[string]interface{}{
			{"key": "secrets_file", "label": "Secrets file", "format": "compliance_with_file"},
			{"key": "database_validation", "label": "Database", "format": "compliance_simple"},
		},
		"subsections": []map[string]interface{}{
			{
				"key":             "reports",
				"title":           "Validation Reports",
				"title_separator": "=",
				"format":          "numbered_list",
			},
		},
	}

	// Validate secrets.yml (if available)
	secretsYMLPath := s.config.GetSecretsFilePath()
	secretsYMLData := make(map[string]interface{})

	if secretsYMLPath != "" {
		// Convert to absolute path for consistency with other file paths
		absSecretsYMLPath := common.MakeAbsolutePath(secretsYMLPath)
		s.logger.Debug(fmt.Sprintf("Validating secrets.yml: %s", absSecretsYMLPath))
		secretsYMLData["file"] = absSecretsYMLPath
		secretsYMLData["checked"] = true

		_, validationErrors := s.validator.ReadAndValidateSecretsYML(secretsYMLPath)
		if len(validationErrors) == 0 {
			secretsYMLData["status"] = "Compliance"
			secretsYMLData["symbol"] = "✓"
			s.logger.Debug("secrets.yml validation: Compliance")
		} else {
			secretsYMLData["status"] = "Not compliance"
			secretsYMLData["symbol"] = "✗"
			s.logger.Debug(fmt.Sprintf("secrets.yml validation: Not compliance (%d errors)", len(validationErrors)))
			allErrors = append(allErrors, addPrefixToErrors(validationErrors, "[Secrets file]")...)
		}
	} else {
		secretsYMLData["checked"] = false
		secretsYMLData["status"] = "Not checked (file not found)"
		s.logger.Debug("secrets.yml validation: Skipped (file not found)")
	}
	validationData["secrets_file"] = secretsYMLData

	// Validate database duplicates (if accessible)
	dbValidationData := make(map[string]interface{})

	if accessible && db != nil {
		s.logger.Debug("Validating database for duplicates...")
		dbValidationData["checked"] = true

		// Create adapter to pass database to validator
		dbAdapter := keepass.NewDatabaseAdapter(db)
		duplicateErrors := s.validator.ValidateKeePassDuplicates(dbAdapter)

		if len(duplicateErrors) == 0 {
			dbValidationData["status"] = "Compliance"
			dbValidationData["symbol"] = "✓"
			s.logger.Debug("Database validation: Compliance")
		} else {
			dbValidationData["status"] = "Not compliance"
			dbValidationData["symbol"] = "✗"
			s.logger.Debug(fmt.Sprintf("Database validation: Not compliance (%d errors)", len(duplicateErrors)))
			allErrors = append(allErrors, addPrefixToErrors(duplicateErrors, "[Database]")...)
		}
	} else {
		dbValidationData["checked"] = false
		dbValidationData["status"] = "Not checked (database not accessible)"
		if !accessible {
			s.logger.Debug("Database validation: Skipped (database not accessible)")
		}
	}
	validationData["database_validation"] = dbValidationData

	// Add reports section only if there are errors
	if len(allErrors) > 0 {
		reports := []string{}
		for _, err := range allErrors {
			reports = append(reports, err.Error())
		}
		validationData["reports"] = reports
		s.logger.Debug(fmt.Sprintf("Validation reports: %d total errors", len(allErrors)))
	}

	statusData["validation"] = validationData

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

// addPrefixToErrors adds a prefix to a list of errors
func addPrefixToErrors(errors []error, prefix string) []error {
	prefixed := make([]error, len(errors))
	for i, err := range errors {
		prefixed[i] = fmt.Errorf("%s %w", prefix, err)
	}
	return prefixed
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

// countEntries recursively counts all entries in the given groups
func countEntries(groups []gokeepasslib.Group) int {
	count := 0
	for _, group := range groups {
		count += len(group.Entries)
		count += countEntries(group.Groups)
	}
	return count
}
