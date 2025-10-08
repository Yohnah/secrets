package common

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/validator"
)

// FileExists checks if a file exists at the given path
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// MakeAbsolutePath converts a relative path to an absolute path
// If the path is already absolute, returns it unchanged
func MakeAbsolutePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	cwd, _ := os.Getwd()
	return filepath.Join(cwd, path)
}

// SecurePassword is a wrapper for password strings that ensures memory cleanup
// This type helps prevent password data from remaining in memory after use
type SecurePassword struct {
	data []byte
}

// NewSecurePassword creates a new SecurePassword from a string
// The password string should be cleared by the caller after creating SecurePassword
func NewSecurePassword(password string) *SecurePassword {
	return &SecurePassword{
		data: []byte(password),
	}
}

// String returns the password as a string
// WARNING: The returned string will remain in memory until garbage collected
// Use this method only when absolutely necessary and clear the result when done
func (sp *SecurePassword) String() string {
	if sp == nil || sp.data == nil {
		return ""
	}
	return string(sp.data)
}

// Clear securely erases the password from memory
// This should be called as soon as the password is no longer needed
func (sp *SecurePassword) Clear() {
	if sp != nil && sp.data != nil {
		// Overwrite memory with zeros
		for i := range sp.data {
			sp.data[i] = 0
		}
		sp.data = nil
	}
}

// GetPassword retrieves password from config or prompts user
// This function implements secure password handling and memory cleanup
//
// Parameters:
//   - cfg: Configuration with Password and NoInteractive fields
//   - prm: PromptManager for interactive password input
//   - log: LoggerManager for debug messages
//   - creating: If true, prompts twice for confirmation (new password)
//
// Returns:
//   - *SecurePassword: Password wrapped in secure container (caller must call Clear() when done)
//   - error: Error if password cannot be obtained
//
// Security: The returned SecurePassword must be cleared after use by calling Clear()
// to prevent password from remaining in memory
func GetPassword(cfg *config.Config, prm prompt.Manager, log logger.Manager, creating bool) (*SecurePassword, error) {
	// Check if password is provided via config (from env var or other sources)
	if cfg.Password != "" {
		log.Debug("Using password from configuration (SECRETS_YOHNAH_PASSWORD environment variable)")
		return NewSecurePassword(cfg.Password), nil
	}

	// If in non-interactive mode and no password provided, fail
	if cfg.NoInteractive {
		return nil, fmt.Errorf("password required. Set SECRETS_YOHNAH_PASSWORD environment variable or remove -f flag")
	}

	// Prompt user for password
	var password string
	var err error

	if creating {
		// Creating new database: ask twice for confirmation
		password, err = prm.PromptPasswordConfirm("Enter database password")
	} else {
		// Verifying existing database: ask once
		password, err = prm.PromptPassword("Enter database password: ")
	}

	if err != nil {
		return nil, err
	}

	return NewSecurePassword(password), nil
}

// ValidateProfileInSecretsYML validates that a profile exists in secrets.yml
//
// Parameters:
//   - secretsFilePath: Path to secrets.yml file
//   - profileName: Name of profile to validate
//   - val: ValidatorManager for reading and validating secrets.yml
//
// Returns:
//   - error: nil if profile exists, error if not found or validation fails
func ValidateProfileInSecretsYML(secretsFilePath, profileName string, val validator.ValidatorManager) error {
	// Check if secrets file path is provided
	if secretsFilePath == "" {
		return fmt.Errorf("secrets.yml file not found. Use --secrets-file flag or set SECRETS_YOHNAH_SECRETS_FILE environment variable")
	}

	// Read and validate secrets.yml
	secretsConfig, errs := val.ReadAndValidateSecretsYML(secretsFilePath)
	if len(errs) > 0 {
		return fmt.Errorf("invalid secrets.yml: %v", errs[0])
	}

	// Check if profile exists in secrets.yml
	for _, profile := range secretsConfig.Profiles {
		if profile.Metadata.Profile == profileName {
			return nil // Profile found
		}
	}

	// Profile not found
	return fmt.Errorf("error: Profile '%s' does not exist in secrets.yml. Please check your configuration", profileName)
}
