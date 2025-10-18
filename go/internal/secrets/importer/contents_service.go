package importer

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
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

// ContentsService handles the import of file contents into KeePass database
type ContentsService interface {
	ImportContents(environmentName string, filePaths []string, decodeBase64 bool) error
}

type contentsService struct {
	configManager    config.Manager
	loggerManager    logger.Manager
	keepassManager   keepass.Manager
	outputManager    output.Manager
	promptManager    prompt.Manager
	validatorManager validator.ValidatorManager
	profileResolver  profile.Resolver
}

// NewContentsService creates a new contents import service
func NewContentsService(
	cfg config.Manager,
	log logger.Manager,
	kp keepass.Manager,
	out output.Manager,
	prm prompt.Manager,
	val validator.ValidatorManager,
	resolver profile.Resolver,
) ContentsService {
	return &contentsService{
		configManager:    cfg,
		loggerManager:    log,
		keepassManager:   kp,
		outputManager:    out,
		promptManager:    prm,
		validatorManager: val,
		profileResolver:  resolver,
	}
}

// ImportContents imports file contents into KeePass database by matching filenames with item names
func (s *contentsService) ImportContents(environmentName string, filePaths []string, decodeBase64 bool) error {
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
	securePassword, err := common.GetPassword(s.configManager, s.promptManager, s.loggerManager, false)
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
		promptMsg := fmt.Sprintf("This will import contents from %d file(s) [%s] into environment '%s' of profile '%s'. Do you want to continue?",
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

		// Read file content
		content, err := os.ReadFile(filePath)
		if err != nil {
			s.loggerManager.Error(fmt.Sprintf("Failed to read file %s: %v", filePath, err))
			continue
		}

		// Decode base64 if requested
		if decodeBase64 {
			decoded, err := base64.StdEncoding.DecodeString(string(content))
			if err != nil {
				s.loggerManager.Error(fmt.Sprintf("Failed to decode base64 content from %s: %v", filePath, err))
				continue
			}
			content = decoded
		}

		// Get filename without path
		fileName := filepath.Base(filePath)

		// Import content
		imported := s.importContentByFilename(
			fileName,
			string(content),
			resolvedProfile,
			environmentName,
		)

		if imported {
			totalImported++
		} else {
			totalIgnored++
		}
	}

	// Step 7: Save database
	if err := s.keepassManager.SaveAndClose(); err != nil {
		return fmt.Errorf("failed to save database: %w", err)
	}

	// Step 8: Report results
	s.loggerManager.Info(fmt.Sprintf("Import complete: %d files imported, %d ignored", totalImported, totalIgnored))

	return nil
}

// importContentByFilename matches filename with items in secrets.yml and stores content in KeePass
func (s *contentsService) importContentByFilename(
	fileName string,
	content string,
	resolvedProfile *profile.ResolvedProfile,
	environmentName string,
) bool {
	// Get items for this environment
	items, exists := resolvedProfile.Profile.Environments[environmentName]
	if !exists {
		return false
	}

	// Find item with matching name
	var matchedItem *validator.Item
	for _, item := range items {
		if item.Name == fileName {
			matchedItem = &item
			break
		}
	}

	if matchedItem == nil {
		s.loggerManager.Info(fmt.Sprintf("No matching item found for file '%s', ignoring", fileName))
		return false
	}

	// Determine if it's an attachment or field
	isAttachment := strings.HasPrefix(matchedItem.Key, "attachments/")

	if isAttachment {
		// Store as attachment
		attachmentName := strings.TrimPrefix(matchedItem.Key, "attachments/")
		entryPath := fmt.Sprintf("%s/HEAD/%s%s", resolvedProfile.Name, environmentName, matchedItem.Entry)

		// Check if attachment exists and delete it
		existingContent, err := s.keepassManager.GetAttachmentContent(
			resolvedProfile.Name,
			environmentName,
			matchedItem.Entry,
			attachmentName,
		)
		if err == nil && existingContent != nil {
			s.loggerManager.Debug(fmt.Sprintf("Attachment '%s' already exists, replacing...", attachmentName))
			if err := s.deleteAttachment(resolvedProfile.Name, environmentName, matchedItem.Entry, attachmentName); err != nil {
				s.loggerManager.Error(fmt.Sprintf("Failed to delete existing attachment %s: %v", attachmentName, err))
				return false
			}
		}

		// Create new attachment
		if err := s.keepassManager.CreateAttachment(
			resolvedProfile.Name,
			environmentName,
			matchedItem.Entry,
			attachmentName,
			[]byte(content),
		); err != nil {
			s.loggerManager.Error(fmt.Sprintf("Failed to create attachment for %s: %v", fileName, err))
			return false
		}

		s.loggerManager.Info(fmt.Sprintf("Stored '%s' as attachment '%s' in %s", fileName, attachmentName, entryPath))
	} else {
		// Store as field (standard or custom)
		var err error
		if s.keepassManager.IsStandardField(matchedItem.Key) {
			// Store as standard field
			err = s.keepassManager.SetStandardField(
				resolvedProfile.Name,
				environmentName,
				matchedItem.Entry,
				matchedItem.Key,
				content,
			)
		} else {
			// Store as custom field
			err = s.keepassManager.SetCustomField(
				resolvedProfile.Name,
				environmentName,
				matchedItem.Entry,
				matchedItem.Key,
				content,
			)
		}

		if err != nil {
			s.loggerManager.Error(fmt.Sprintf("Failed to set field for %s: %v", fileName, err))
			return false
		}

		entryPath := fmt.Sprintf("%s/HEAD/%s%s", resolvedProfile.Name, environmentName, matchedItem.Entry)
		s.loggerManager.Info(fmt.Sprintf("Stored '%s' in field '%s' of %s", fileName, matchedItem.Key, entryPath))
	}

	return true
}

// deleteAttachment removes an attachment from an entry
func (s *contentsService) deleteAttachment(profileName, envName, entryPath, attachmentName string) error {
	db := s.keepassManager.GetDatabase()
	if db == nil {
		return fmt.Errorf("database not open")
	}

	fullPath := fmt.Sprintf("%s/HEAD/%s%s", profileName, envName, entryPath)
	entry := s.findEntryByPath(db, fullPath)
	if entry == nil {
		return fmt.Errorf("entry not found: %s", fullPath)
	}

	// Remove binary reference from entry
	for i, binary := range entry.Binaries {
		if binary.Name == attachmentName {
			entry.Binaries = append(entry.Binaries[:i], entry.Binaries[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("attachment not found: %s", attachmentName)
}

// findEntryByPath navigates the group tree to find an entry by path
func (s *contentsService) findEntryByPath(db *gokeepasslib.Database, path string) *gokeepasslib.Entry {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 {
		return nil
	}

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

	entryName := parts[len(parts)-1]
	for i := range currentGroup.Entries {
		if currentGroup.Entries[i].GetTitle() == entryName {
			return &currentGroup.Entries[i]
		}
	}

	return nil
}
