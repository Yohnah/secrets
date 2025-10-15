package show

import (
	"fmt"
	"strings"

	"github.com/Yohnah/secrets/internal/secrets/common"
	"github.com/Yohnah/secrets/internal/validator"
)

// SyncedDataItem represents the sync status of a single item
type SyncedDataItem struct {
	Name             string `json:"name" yaml:"name"`
	Status           string `json:"status" yaml:"status"`
	Issue            string `json:"issue" yaml:"issue"`
	FieldValueStatus string `json:"field_value_status" yaml:"field_value_status"`
}

// SyncedData displays synchronization status between secrets.yml and KeePass database
func (s *service) SyncedData(profileFilter string) error {
	// Step 1: Read and validate secrets.yml
	secretsFilePath := s.config.GetSecretsFilePath()
	if secretsFilePath == "" {
		return fmt.Errorf("secrets.yml file not found. Use --secrets-file flag or set SECRETS_YOHNAH_SECRETS_FILE environment variable")
	}

	secretsConfig, errs := s.validator.ReadAndValidateSecretsYML(secretsFilePath)
	if len(errs) > 0 {
		return fmt.Errorf("invalid secrets.yml: %v", errs[0])
	}

	// Step 2: Determine which profile to check
	var profileToCheck validator.Profile
	if profileFilter == "" {
		// Auto-detect profile (must be single profile)
		if len(secretsConfig.Profiles) == 0 {
			return fmt.Errorf("no profiles found in secrets.yml")
		}
		if len(secretsConfig.Profiles) > 1 {
			return fmt.Errorf("multiple profiles found in secrets.yml. Please specify a profile using --profile-name flag")
		}
		profileToCheck = secretsConfig.Profiles[0]
	} else {
		// Find specified profile
		found := false
		for _, profile := range secretsConfig.Profiles {
			if profile.Metadata.Profile == profileFilter {
				profileToCheck = profile
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("profile '%s' not found in secrets.yml", profileFilter)
		}
	}

	profileName := profileToCheck.Metadata.Profile

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
	defer securePassword.Clear()

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

	// Step 6: Check sync status for each item in each environment
	var allItems []SyncedDataItem

	for envName, items := range profileToCheck.Environments {
		// Process each item in the environment
		for _, item := range items {
			syncItem := SyncedDataItem{
				Name:             fmt.Sprintf("%s/%s", envName, item.Name),
				Status:           "✓",
				Issue:            "OK",
				FieldValueStatus: "N/A",
			}

			// Determine entry path
			entryPath := item.Entry
			if entryPath == "" {
				syncItem.Status = "✗"
				syncItem.Issue = "Missing entry path in secrets.yml"
				syncItem.FieldValueStatus = "N/A"
				allItems = append(allItems, syncItem)
				continue
			}

			// Check key (optimization: FieldExists already checks entry existence)
			keyName := item.Key
			if keyName == "" {
				syncItem.Status = "✗"
				syncItem.Issue = "Missing key name in secrets.yml"
				syncItem.FieldValueStatus = "N/A"
				allItems = append(allItems, syncItem)
				continue
			}

			exists, err := s.keepass.FieldExists(profileName, envName, entryPath, keyName)
			if err != nil {
				// FieldExists failed - need to check if it's entry missing or key missing
				entryExists, entryErr := s.keepass.EntryExists(profileName, envName, entryPath)
				if entryErr != nil || !entryExists {
					// Entry doesn't exist
					syncItem.Status = "✗"
					syncItem.Issue = "Missing entry"
					syncItem.FieldValueStatus = "N/A"
				} else {
					// Entry exists but key doesn't
					syncItem.Status = "✗"
					syncItem.Issue = fmt.Sprintf("Missing key: %s", keyName)
					syncItem.FieldValueStatus = "N/A"
				}
			} else if !exists {
				// Key doesn't exist
				syncItem.Status = "✗"
				syncItem.Issue = fmt.Sprintf("Missing key: %s", keyName)
				syncItem.FieldValueStatus = "N/A"
			} else {
				// Field exists - determine if it's an attachment or regular field
				if strings.HasPrefix(keyName, "attachments/") {
					// Handle attachment
					attachmentName := strings.TrimPrefix(keyName, "attachments/")
					content, err := s.keepass.GetAttachmentContent(profileName, envName, entryPath, attachmentName)
					if err != nil {
						// Error getting attachment content - log for debugging
						s.logger.Debug(fmt.Sprintf("ERROR getting attachment '%s' from entry '%s': %v", attachmentName, entryPath, err))
						syncItem.FieldValueStatus = "N/A"
					} else {
						// Determine attachment value status
						contentStr := string(content)
						if len(content) == 0 {
							syncItem.FieldValueStatus = "empty"
						} else if contentStr == "Attachment pending to be filled by the developer" {
							syncItem.FieldValueStatus = "default"
						} else {
							syncItem.FieldValueStatus = "has_data"
						}
					}
				} else {
					// Handle regular field
					value, err := s.keepass.GetFieldValue(profileName, envName, entryPath, keyName)
					if err != nil {
						// Error getting value
						syncItem.FieldValueStatus = "N/A"
					} else {
						// Determine field value status
						if value == "" {
							syncItem.FieldValueStatus = "empty"
						} else if value == "Field pending to be filled by the developer" {
							syncItem.FieldValueStatus = "default"
						} else {
							syncItem.FieldValueStatus = "has_data"
						}
					}
				}
			}

			allItems = append(allItems, syncItem)
		}
	}

	// Step 7: Output results
	// Convert items to []interface{} for OutputManager compatibility
	items := make([]interface{}, len(allItems))
	for i, item := range allItems {
		items[i] = map[string]interface{}{
			"name":               item.Name,
			"status":             item.Status,
			"issue":              item.Issue,
			"field_value_status": item.FieldValueStatus,
		}
	}

	outputData := map[string]interface{}{
		"items": items,
		"_display": map[string]interface{}{
			"format": "synced_data_list",
			"title":  fmt.Sprintf("Sync Status: %s", profileName),
		},
	}

	return s.output.Output(outputData, cfg.OutputFormat)
}
