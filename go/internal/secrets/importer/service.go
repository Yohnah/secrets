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

			// Check if attachment exists, if so delete it first
			existingContent, err := s.keepassManager.GetAttachmentContent(
				resolvedProfile.Name,
				environmentName,
				item.Entry,
				filename,
			)
			if err == nil && existingContent != nil {
				// Attachment exists, delete it first to force replacement
				s.loggerManager.Debug(fmt.Sprintf("Attachment '%s' already exists, deleting before import...", filename))
				if err := s.keepassManager.DeleteAttachment(
					resolvedProfile.Name,
					environmentName,
					item.Entry,
					filename,
				); err != nil {
					s.loggerManager.Error(fmt.Sprintf("Failed to delete existing attachment for '%s': %v", varName, err))
					ignored++
					continue
				}
			}

			// Store as attachment (now it will be created fresh)
			dataBytes := []byte(varValue)
			
			if err := s.keepassManager.CreateAttachment(
				resolvedProfile.Name,
				environmentName,
				item.Entry,
				filename,
				dataBytes,
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
