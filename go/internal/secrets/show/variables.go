package show

import (
	"fmt"
	"strings"

	"github.com/Yohnah/secrets/internal/secrets/common"
	"github.com/Yohnah/secrets/internal/template"
	"github.com/Yohnah/secrets/internal/validator"
)

// Variables retrieves and displays environment variables (type=envvar) from a profile environment
func (s *service) Variables(environmentName, outputFormat, customTemplateContent string, withNoValues bool) error {
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

	// Filter items with type="envvar"
	envVarItems := make([]validator.Item, 0)
	for _, item := range environmentItems {
		if strings.ToLower(item.Type) == "envvar" {
			envVarItems = append(envVarItems, item)
		}
	}

	if len(envVarItems) == 0 {
		return fmt.Errorf("no environment variables (type=envvar) found in environment '%s'", environmentName)
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

	// Build the items map with variable names and values
	itemsMap := make(map[string]string)

	for _, item := range envVarItems {
		// Remove leading slash if present from entry path
		entryPath := item.Entry
		if len(entryPath) > 0 && entryPath[0] == '/' {
			entryPath = entryPath[1:]
		}

		// Determine if this is an attachment or a field
		fieldName := item.Key
		isAttachment := strings.HasPrefix(fieldName, "attachments/")

		var value string
		var err error

		if isAttachment {
			// Extract attachment name (remove "attachments/" prefix)
			attachmentName := strings.TrimPrefix(fieldName, "attachments/")

			// Get attachment content from KeePass
			attachmentData, attachErr := s.keepass.GetAttachmentContent(profileName, environmentName, entryPath, attachmentName)
			if attachErr != nil {
				s.logger.Info(fmt.Sprintf("Attachment '%s' not found in entry '%s/%s/%s', skipping",
					attachmentName, profileName, environmentName, entryPath))
				continue
			}
			value = string(attachmentData)
		} else {
			// Try to get the field value from KeePass
			value, err = s.keepass.GetFieldValue(profileName, environmentName, entryPath, fieldName)
			if err != nil {
				s.logger.Info(fmt.Sprintf("Field '%s' not found in entry '%s/%s/%s', skipping",
					fieldName, profileName, environmentName, entryPath))
				continue
			}
		}

		// Use the item name as the variable name
		// If withNoValues is true, use empty string instead of actual value
		if withNoValues {
			itemsMap[item.Name] = ""
		} else {
			itemsMap[item.Name] = value
		}
	}

	if len(itemsMap) == 0 {
		return fmt.Errorf("no values retrieved from KeePass for environment '%s'", environmentName)
	}

	// Prepare template data
	templateData := template.TemplateData{
		Section:     "variables",
		Environment: environmentName,
		Profile:     profileName,
		Items:       itemsMap,
	}

	// Render the output
	var rendered string

	if customTemplateContent != "" {
		// Render using custom template content
		rendered, err = s.template.RenderCustomTemplate(customTemplateContent, templateData)
		if err != nil {
			return fmt.Errorf("failed to render custom template: %w", err)
		}
	} else {
		// Normalize output format to template name with extension
		templateName := normalizeOutputFormat(outputFormat)

		// Render using built-in template for the specified format
		rendered, err = s.template.RenderTemplate(templateName, templateData)
		if err != nil {
			return fmt.Errorf("failed to render template: %w", err)
		}
	}

	// Print the rendered output using OutputManager
	if err := s.output.OutputRaw(rendered); err != nil {
		return fmt.Errorf("failed to print output: %w", err)
	}

	return nil
}

// normalizeOutputFormat converts short format names to full template names
// Examples: "json" -> "json.json", "yaml" -> "yaml.yml", "k8s" -> "k8s.yml"
func normalizeOutputFormat(format string) string {
	// Map of short format names to full template names
	formatMap := map[string]string{
		"json":        "json.json",
		"yaml":        "yaml.yml",
		"dotenv":      "dotenv.env",
		"k8s":         "k8s.yml",
		"sh":          "shell.sh",
		"bash":        "shell.sh",
		"zsh":         "shell.sh",
		"shell.sh":    "shell.sh",
		"shell.bash":  "shell.sh",
		"shell.zsh":   "shell.sh",
		"cmd":         "shell.cmd",
		"bat":         "shell.cmd",
		"shell.cmd":   "shell.cmd",
		"shell.bat":   "shell.cmd",
		"ps1":         "shell.ps1",
		"powershell":  "shell.ps1",
		"shell.ps1":   "shell.ps1",
		"csh":         "shell.csh",
		"shell.csh":   "shell.csh",
		"fish":        "shell.fish",
		"shell.fish":  "shell.fish",
		"nu":          "shell.nu",
		"nushell":     "shell.nu",
		"shell.nu":    "shell.nu",
		"spring_boot": "spring_boot.properties",
		"terraform":   "terraform.tfvars",
		"toml":        "toml.toml",
		"ansible":     "ansible.yml",
		"docker":      "docker-compose.yml",
		"dotnet":      "dotnet.json",
	}

	// If format already has proper extension, return as-is
	if mapped, exists := formatMap[format]; exists {
		return mapped
	}

	// Return as-is if not in map (might already be full name)
	return format
}
