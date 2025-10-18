package show

import (
	"fmt"
	"strings"

	"github.com/Yohnah/secrets/internal/secrets/common"
	"github.com/Yohnah/secrets/internal/validator"
)

// SSHKeyInfo represents information about a single SSH key item
type SSHKeyInfo struct {
	Name      string `json:"name" yaml:"name"`
	EntryPath string `json:"entry_path" yaml:"entry_path"`
}

// SSHKeys lists all SSH key items (type=sshkey) in an environment
// This method does NOT require KeePass access, it only reads from secrets.yml
func (s *service) SSHKeys(environmentName, outputFormat string) error {
	// Resolve profile (auto-detect when no profile specified)
	resolvedProfile, err := s.profileResolver.Resolve("")
	if err != nil {
		return err
	}
	profileName := resolvedProfile.Name

	if resolvedProfile.Profile == nil {
		return fmt.Errorf("profile '%s' is invalid in secrets.yml", profileName)
	}

	// Find the environment within the profile
	environmentItems, exists := resolvedProfile.Profile.Environments[environmentName]
	if !exists {
		return fmt.Errorf("environment '%s' does not exist in profile '%s'", environmentName, profileName)
	}

	// Filter items with type="sshkey"
	sshKeyItems := make([]interface{}, 0)
	for _, item := range environmentItems {
		if strings.ToLower(item.Type) == "sshkey" {
			sshKeyItems = append(sshKeyItems, map[string]interface{}{
				"name":       item.Name,
				"entry_path": fmt.Sprintf("%s/%s/%s", profileName, environmentName, strings.TrimPrefix(item.Entry, "/")),
			})
		}
	}

	if len(sshKeyItems) == 0 {
		return fmt.Errorf("no SSH keys (type=sshkey) found in environment '%s'", environmentName)
	}

	// Prepare payload for output with display metadata for table format
	payload := map[string]interface{}{
		"profile":     profileName,
		"environment": environmentName,
		"sshkeys":     sshKeyItems,
		"_display": map[string]interface{}{
			"title":  fmt.Sprintf("SSH Keys in %s/%s", profileName, environmentName),
			"format": "sshkeys_list",
		},
	}

	// Render output using OutputManager
	if err := s.output.Output(payload, outputFormat); err != nil {
		return fmt.Errorf("failed to render output: %w", err)
	}

	return nil
}

// SSHKeyContent retrieves and displays the SSH private key content from KeePass attachment
// This method REQUIRES KeePass access to retrieve the attachment content
func (s *service) SSHKeyContent(environmentName, itemName string) error {
	// Resolve profile (auto-detect when no profile specified)
	resolvedProfile, err := s.profileResolver.Resolve("")
	if err != nil {
		return err
	}
	profileName := resolvedProfile.Name

	if resolvedProfile.Profile == nil {
		return fmt.Errorf("profile '%s' is invalid in secrets.yml", profileName)
	}

	// Find the environment within the profile
	environmentItems, exists := resolvedProfile.Profile.Environments[environmentName]
	if !exists {
		return fmt.Errorf("environment '%s' does not exist in profile '%s'", environmentName, profileName)
	}

	// Find the specific item by name
	var targetItem *validator.Item
	for _, item := range environmentItems {
		if item.Name == itemName {
			targetItem = &item
			break
		}
	}

	if targetItem == nil {
		return fmt.Errorf("item '%s' not found in environment '%s'", itemName, environmentName)
	}

	// Verify that the item is of type sshkey
	if strings.ToLower(targetItem.Type) != "sshkey" {
		return fmt.Errorf("item '%s' is not of type 'sshkey' (found type '%s')", itemName, targetItem.Type)
	}

	// Verify that the key field is an attachment
	fieldName := targetItem.Key
	if !strings.HasPrefix(fieldName, "attachments/") {
		return fmt.Errorf("item '%s' does not reference an attachment (key: '%s')", itemName, fieldName)
	}

	// Get configuration
	_, err = s.config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Get password (secure)
	securePassword, err := common.GetPassword(s.config, s.prompt, s.logger, false)
	if err != nil {
		return err
	}
	defer securePassword.Clear()

	// Open database
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

	// Remove leading slash if present from entry path
	entryPath := targetItem.Entry
	if len(entryPath) > 0 && entryPath[0] == '/' {
		entryPath = entryPath[1:]
	}

	// Extract attachment name (remove "attachments/" prefix)
	attachmentName := strings.TrimPrefix(fieldName, "attachments/")

	// Get attachment content from KeePass
	attachmentData, err := s.keepass.GetAttachmentContent(profileName, environmentName, entryPath, attachmentName)
	if err != nil {
		return fmt.Errorf("failed to retrieve SSH key attachment '%s' from entry '%s/%s/%s': %w",
			attachmentName, profileName, environmentName, entryPath, err)
	}

	// Output raw content (the private key)
	if err := s.output.OutputRaw(string(attachmentData)); err != nil {
		return fmt.Errorf("failed to output SSH key content: %w", err)
	}

	return nil
}
