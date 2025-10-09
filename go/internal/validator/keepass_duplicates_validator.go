package validator

import (
	"fmt"
	"strings"
)

// KeePassManager defines the interface for reading KeePass database structure
// This interface is used by ValidatorManager to validate database integrity
type KeePassManager interface {
	GetRootGroups() ([]string, error)
	GetGroupsByParent(parentPath string) ([]string, error)
	GetEntriesByGroup(groupPath string) ([]string, error)
	GetFieldsByEntry(entryPath string) ([]string, error)
	GetEntriesByEnvironment(profileName, envName string) ([]string, error)
}

// ValidateKeePassDuplicates checks for duplicate elements in KeePass database
// Returns list of all duplicate errors found, or nil if database is valid
// This function ONLY validates duplicates, not complete structure
func (m *manager) ValidateKeePassDuplicates(db KeePassManager) []error {
	var errors []error

	// Validate profile duplicates at ROOT level
	profileErrors := validateProfileDuplicates(db)
	errors = append(errors, profileErrors...)

	// Get all profiles for further validation
	profiles, err := db.GetRootGroups()
	if err != nil {
		errors = append(errors, fmt.Errorf("failed to read root groups: %w", err))
		return errors
	}

	// Validate each profile structure
	for _, profileName := range profiles {
		// Validate HEAD duplicates within profile
		headErrors := validateHEADDuplicates(db, profileName)
		errors = append(errors, headErrors...)

		// Get tree groups (HEAD, v1, v2, etc.)
		treeGroups, err := db.GetGroupsByParent(profileName)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to read tree groups for profile '%s': %w", profileName, err))
			continue
		}

		// Validate each tree group (focus on HEAD)
		for _, treeGroup := range treeGroups {
			treePath := fmt.Sprintf("%s/%s", profileName, treeGroup)

			// Validate environment duplicates within tree group
			envErrors := validateEnvironmentDuplicates(db, profileName, treeGroup)
			errors = append(errors, envErrors...)

			// Get environments in this tree group
			environments, err := db.GetGroupsByParent(treePath)
			if err != nil {
				errors = append(errors, fmt.Errorf("failed to read environments for '%s': %w", treePath, err))
				continue
			}

			// Validate each environment
			for _, envName := range environments {
				envPath := fmt.Sprintf("%s/%s", treePath, envName)

				// Validate entry path duplicates within environment
				entryErrors := validateEntryPathDuplicates(db, profileName, treeGroup, envName)
				errors = append(errors, entryErrors...)

				// Get entries in this environment
				entries, err := db.GetEntriesByGroup(envPath)
				if err != nil {
					errors = append(errors, fmt.Errorf("failed to read entries for '%s': %w", envPath, err))
					continue
				}

				// Validate keys/fields for each entry
				for _, entryPath := range entries {
					fullEntryPath := fmt.Sprintf("%s/%s", envPath, entryPath)
					keyErrors := validateKeyDuplicates(db, fullEntryPath)
					errors = append(errors, keyErrors...)
				}
			}
		}
	}

	// Return nil if no errors found, otherwise return all errors
	if len(errors) == 0 {
		return nil
	}
	return errors
}

// validateProfileDuplicates checks for duplicate profile names at ROOT level
func validateProfileDuplicates(db KeePassManager) []error {
	var errors []error

	profiles, err := db.GetRootGroups()
	if err != nil {
		return []error{fmt.Errorf("failed to read root groups: %w", err)}
	}

	// Track profile names and their occurrences
	seen := make(map[string]int)
	for _, profileName := range profiles {
		seen[profileName]++
	}

	// Report duplicates
	for profileName, count := range seen {
		if count > 1 {
			errors = append(errors, fmt.Errorf(
				"duplicate profile '%s' found in database\n"+
					"  Location: ROOT level\n"+
					"  Found: %d occurrences\n"+
					"  Action: Remove duplicate profile using KeePass client",
				profileName, count))
		}
	}

	return errors
}

// validateHEADDuplicates checks for duplicate HEAD groups within a profile
func validateHEADDuplicates(db KeePassManager, profileName string) []error {
	var errors []error

	groups, err := db.GetGroupsByParent(profileName)
	if err != nil {
		return []error{fmt.Errorf("failed to read groups for profile '%s': %w", profileName, err)}
	}

	// Track group names and their occurrences
	seen := make(map[string]int)
	for _, groupName := range groups {
		seen[groupName]++
	}

	// Report duplicates (especially HEAD which should be unique)
	for groupName, count := range seen {
		if count > 1 {
			errors = append(errors, fmt.Errorf(
				"duplicate tree group '%s' found in profile '%s'\n"+
					"  Location: /%s\n"+
					"  Found: %d occurrences\n"+
					"  Action: Remove duplicate group using KeePass client",
				groupName, profileName, profileName, count))
		}
	}

	return errors
}

// validateEnvironmentDuplicates checks for duplicate environments within a tree group
func validateEnvironmentDuplicates(db KeePassManager, profileName, treeGroup string) []error {
	var errors []error

	treePath := fmt.Sprintf("%s/%s", profileName, treeGroup)
	environments, err := db.GetGroupsByParent(treePath)
	if err != nil {
		return []error{fmt.Errorf("failed to read environments for '%s': %w", treePath, err)}
	}

	// Track environment names and their occurrences
	seen := make(map[string]int)
	for _, envName := range environments {
		seen[envName]++
	}

	// Report duplicates
	for envName, count := range seen {
		if count > 1 {
			errors = append(errors, fmt.Errorf(
				"duplicate environment '%s' found in profile '%s'\n"+
					"  Location: /%s/%s\n"+
					"  Found: %d occurrences\n"+
					"  Action: Remove duplicate environment using KeePass client",
				envName, profileName, profileName, treeGroup, count))
		}
	}

	return errors
}

// validateEntryPathDuplicates checks for duplicate entry paths within an environment
func validateEntryPathDuplicates(db KeePassManager, profileName, treeGroup, envName string) []error {
	var errors []error

	envPath := fmt.Sprintf("%s/%s/%s", profileName, treeGroup, envName)
	entries, err := db.GetEntriesByGroup(envPath)
	if err != nil {
		return []error{fmt.Errorf("failed to read entries for '%s': %w", envPath, err)}
	}

	// Track entry paths and their occurrences
	seen := make(map[string]int)
	for _, entryPath := range entries {
		// Normalize path for comparison (remove leading /)
		normalizedPath := strings.TrimPrefix(entryPath, "/")
		seen[normalizedPath]++
	}

	// Report duplicates
	for entryPath, count := range seen {
		if count > 1 {
			errors = append(errors, fmt.Errorf(
				"duplicate entry path '/%s' found in environment '%s'\n"+
					"  Location: /%s/%s/%s\n"+
					"  Found: %d occurrences\n"+
					"  Action: Remove duplicate entry using KeePass client",
				entryPath, envName, profileName, treeGroup, envName, count))
		}
	}

	return errors
}

// validateKeyDuplicates checks for duplicate keys/fields within an entry
func validateKeyDuplicates(db KeePassManager, entryPath string) []error {
	var errors []error

	fields, err := db.GetFieldsByEntry(entryPath)
	if err != nil {
		return []error{fmt.Errorf("failed to read fields for entry '%s': %w", entryPath, err)}
	}

	// Track field names and their occurrences
	// Standard fields are case-insensitive, custom fields are case-sensitive
	standardFields := map[string]bool{
		"title":    true,
		"username": true,
		"password": true,
		"url":      true,
		"notes":    true,
	}

	seenStandard := make(map[string]int)    // Lowercase for case-insensitive comparison
	seenCustom := make(map[string]int)      // Exact case for case-sensitive comparison
	seenAttachments := make(map[string]int) // Attachments

	for _, fieldName := range fields {
		// Check if it's an attachment
		if strings.HasPrefix(fieldName, "attachments/") {
			seenAttachments[fieldName]++
		} else {
			// Check if it's a standard field (case-insensitive)
			lowerField := strings.ToLower(fieldName)
			if standardFields[lowerField] {
				seenStandard[lowerField]++
			} else {
				// Custom field (case-sensitive)
				seenCustom[fieldName]++
			}
		}
	}

	// Report duplicates for standard fields
	for fieldName, count := range seenStandard {
		if count > 1 {
			errors = append(errors, fmt.Errorf(
				"duplicate standard field '%s' found in entry\n"+
					"  Location: %s\n"+
					"  Found: %d occurrences\n"+
					"  Action: Remove duplicate field using KeePass client",
				fieldName, entryPath, count))
		}
	}

	// Report duplicates for custom fields
	for fieldName, count := range seenCustom {
		if count > 1 {
			errors = append(errors, fmt.Errorf(
				"duplicate custom field '%s' found in entry\n"+
					"  Location: %s\n"+
					"  Found: %d occurrences\n"+
					"  Action: Remove duplicate field using KeePass client",
				fieldName, entryPath, count))
		}
	}

	// Report duplicates for attachments
	for attachmentName, count := range seenAttachments {
		if count > 1 {
			errors = append(errors, fmt.Errorf(
				"duplicate attachment '%s' found in entry\n"+
					"  Location: %s\n"+
					"  Found: %d occurrences\n"+
					"  Action: Remove duplicate attachment using KeePass client",
				attachmentName, entryPath, count))
		}
	}

	return errors
}
