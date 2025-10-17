package importer

import (
	"fmt"
	"strings"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/output"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets/common"
	"github.com/Yohnah/secrets/internal/secrets/profile"
	"github.com/Yohnah/secrets/internal/validator"
	"github.com/tobischo/gokeepasslib/v3"
)

// Service handles the import of variables and contents into KeePass database
type Service interface {
	ImportVariables(environmentName string, filePaths []string, decodeBase64 bool) error
	ImportContents(environmentName string, filePaths []string, decodeBase64 bool) error
}

type service struct {
	configManager    config.Manager
	loggerManager    logger.Manager
	keepassManager   keepass.Manager
	outputManager    output.Manager
	promptManager    prompt.Manager
	validatorManager validator.ValidatorManager
	profileResolver  profile.Resolver
}

// NewService creates a new import service
func NewService(
	cfg config.Manager,
	log logger.Manager,
	kp keepass.Manager,
	out output.Manager,
	prm prompt.Manager,
	val validator.ValidatorManager,
	resolver profile.Resolver,
) Service {
	return &service{
		configManager:    cfg,
		loggerManager:    log,
		keepassManager:   kp,
		outputManager:    out,
		promptManager:    prm,
		validatorManager: val,
		profileResolver:  resolver,
	}
}

// ImportVariables imports variables from files into KeePass database
func (s *service) ImportVariables(environmentName string, filePaths []string, decodeBase64 bool) error {
	// Step 1: Resolve profile (auto-detect if not specified)
	resolvedProfile, err := s.profileResolver.Resolve("")
	if err != nil {
		return err
	}

	s.loggerManager.Info(fmt.Sprintf("Using profile: %s", resolvedProfile.Name))

	// Step 2: Validate environment exists in profile
	envExists := false
	for envName := range resolvedProfile.Profile.Environments {
		if envName == environmentName {
			envExists = true
			break
		}
	}

	if !envExists {
		return fmt.Errorf("environment '%s' does not exist in profile '%s'", environmentName, resolvedProfile.Name)
	}

	// Step 3: Get password
	securePassword, err := common.GetPassword(s.configManager, nil, s.loggerManager, false)
	if err != nil {
		return err
	}
	defer securePassword.Clear()

	// Step 4: Open database
	dbPath := s.configManager.GetDatabasePath()
	keyfilePath := s.configManager.GetKeyfilePath()

	// Ensure no previous session is open
	if s.keepassManager.IsOpen() {
		s.keepassManager.CloseWithoutSave()
	}

	if err := s.keepassManager.Open(dbPath, keyfilePath, securePassword.String()); err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() {
		if s.keepassManager.IsOpen() {
			if err := s.keepassManager.CloseWithoutSave(); err != nil {
				s.loggerManager.Error(fmt.Sprintf("Failed to close database: %v", err))
			}
		}
	}()

	// Step 5: Ask for confirmation unless --force is set
	cfg, err := s.configManager.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}

	if !cfg.NoInteractive {
		fileList := strings.Join(filePaths, ", ")
		promptMsg := fmt.Sprintf("This will import variables from %d file(s) [%s] into environment '%s' of profile '%s'. Do you want to continue?",
			len(filePaths), fileList, environmentName, resolvedProfile.Name)

		confirmed, err := s.promptManager.ConfirmWithDefault(promptMsg, false)
		if err != nil {
			return fmt.Errorf("failed to get confirmation: %w", err)
		}

		if !confirmed {
			s.loggerManager.Info("Import cancelled by user")
			return nil
		}
	}

	// Step 6: Process each file
	totalImported := 0
	totalIgnored := 0

	for _, filePath := range filePaths {
		s.loggerManager.Info(fmt.Sprintf("Processing file: %s", filePath))

		// Parse file
		variables, err := ParseFile(filePath, decodeBase64)
		if err != nil {
			s.loggerManager.Error(fmt.Sprintf("Failed to parse file %s: %v", filePath, err))
			continue
		}

		s.loggerManager.Info(fmt.Sprintf("Found %d variables in file", len(variables)))

		// Import variables
		imported, ignored := s.importVariablesFromMap(
			variables,
			resolvedProfile,
			environmentName,
		)

		totalImported += imported
		totalIgnored += ignored
	}

	// Step 7: Save database
	if err := s.keepassManager.SaveAndClose(); err != nil {
		return fmt.Errorf("failed to save database: %w", err)
	}

	// Step 8: Report results
	s.loggerManager.Info(fmt.Sprintf("Import complete: %d variables imported, %d ignored", totalImported, totalIgnored))

	return nil
}

// importVariablesFromMap matches variables with items in secrets.yml and stores them in KeePass
func (s *service) importVariablesFromMap(
	variables map[string]string,
	resolvedProfile *profile.ResolvedProfile,
	environmentName string,
) (imported int, ignored int) {
	// Get items for this environment
	items, exists := resolvedProfile.Profile.Environments[environmentName]
	if !exists {
		return 0, len(variables)
	}

	// Create a map of item names for quick lookup
	itemMap := make(map[string]*validator.Item)
	for i := range items {
		itemMap[items[i].Name] = &items[i]
	}

	// Process each variable
	for varName, varValue := range variables {
		// Check if item exists in secrets.yml
		item, exists := itemMap[varName]
		if !exists {
			s.loggerManager.Debug(fmt.Sprintf("Variable '%s' not found in secrets.yml, ignoring", varName))
			ignored++
			continue
		}

		// Check if key is an attachment
		if strings.HasPrefix(item.Key, "attachments/") {
			// Extract filename from key
			filename := strings.TrimPrefix(item.Key, "attachments/")

			// Check if attachment already exists and delete it to force replacement
			existingContent, err := s.keepassManager.GetAttachmentContent(
				resolvedProfile.Name,
				environmentName,
				item.Entry,
				filename,
			)
			if err == nil && existingContent != nil {
				// Attachment exists, need to delete it first by removing it from entry binaries
				s.loggerManager.Debug(fmt.Sprintf("Attachment '%s' already exists, replacing...", filename))
				if err := s.deleteAttachment(resolvedProfile.Name, environmentName, item.Entry, filename); err != nil {
					s.loggerManager.Error(fmt.Sprintf("Failed to delete existing attachment for '%s': %v", varName, err))
					ignored++
					continue
				}
			}

			// Store as attachment (now it will be created fresh)
			if err := s.keepassManager.CreateAttachment(
				resolvedProfile.Name,
				environmentName,
				item.Entry,
				filename,
				[]byte(varValue),
			); err != nil {
				s.loggerManager.Error(fmt.Sprintf("Failed to set attachment for '%s': %v", varName, err))
				ignored++
				continue
			}

			s.loggerManager.Debug(fmt.Sprintf("Imported '%s' as attachment '%s' in entry '%s'", varName, filename, item.Entry))
		} else {
			// Determine if it's a standard field or custom field
			if s.keepassManager.IsStandardField(item.Key) {
				// Store as standard field
				if err := s.keepassManager.SetStandardField(
					resolvedProfile.Name,
					environmentName,
					item.Entry,
					item.Key,
					varValue,
				); err != nil {
					s.loggerManager.Error(fmt.Sprintf("Failed to set standard field for '%s': %v", varName, err))
					ignored++
					continue
				}
			} else {
				// Store as custom field
				if err := s.keepassManager.SetCustomField(
					resolvedProfile.Name,
					environmentName,
					item.Entry,
					item.Key,
					varValue,
				); err != nil {
					s.loggerManager.Error(fmt.Sprintf("Failed to set custom field for '%s': %v", varName, err))
					ignored++
					continue
				}
			}

			s.loggerManager.Debug(fmt.Sprintf("Imported '%s' to field '%s' in entry '%s'", varName, item.Key, item.Entry))
		}

		imported++
	}

	return imported, ignored
}

// deleteAttachment removes an attachment from an entry
// This is a helper method since KeePassManager doesn't provide a delete method
func (s *service) deleteAttachment(profileName, envName, entryPath, attachmentName string) error {
	// We need to access the database directly to remove the attachment
	// Since we can't delete through the interface, we'll use GetDatabase() if available
	// For now, we'll work around this by getting the entry and removing the binary reference

	// Get the database
	db := s.keepassManager.GetDatabase()
	if db == nil {
		return fmt.Errorf("database not open")
	}

	// Find the entry
	fullPath := fmt.Sprintf("/%s/HEAD/%s%s", profileName, envName, entryPath)
	entry := findEntryByPath(db, fullPath)
	if entry == nil {
		return fmt.Errorf("entry not found: %s", fullPath)
	}

	// Remove the attachment from the entry
	newBinaries := make([]gokeepasslib.BinaryReference, 0)
	for _, binary := range entry.Binaries {
		if binary.Name != attachmentName {
			newBinaries = append(newBinaries, binary)
		}
	}
	entry.Binaries = newBinaries

	return nil
}

// findEntryByPath finds an entry in the database by its full path
func findEntryByPath(db *gokeepasslib.Database, path string) *gokeepasslib.Entry {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 {
		return nil
	}

	// Navigate through groups
	currentGroup := &db.Content.Root.Groups[0]
	for i := 0; i < len(parts)-1; i++ {
		found := false
		for j := range currentGroup.Groups {
			if currentGroup.Groups[j].Name == parts[i] {
				currentGroup = &currentGroup.Groups[j]
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}

	// Find the entry in the last group
	entryName := parts[len(parts)-1]
	for i := range currentGroup.Entries {
		if currentGroup.Entries[i].GetTitle() == entryName {
			return &currentGroup.Entries[i]
		}
	}

	return nil
}

// ImportContents imports file contents into KeePass database by matching filenames
func (s *service) ImportContents(environmentName string, filePaths []string, decodeBase64 bool) error {
	// Create a contents service and delegate
	contentsService := NewContentsService(
		s.configManager,
		s.loggerManager,
		s.keepassManager,
		s.outputManager,
		s.promptManager,
		s.validatorManager,
		s.profileResolver,
	)
	
	return contentsService.ImportContents(environmentName, filePaths, decodeBase64)
}
