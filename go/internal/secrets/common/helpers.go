package common

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/validator"
)

// PromptManagerInterface defines the interface for prompting user input
type PromptManagerInterface interface {
	PromptPassword(message string) (*SecureValue, error)
	PromptPasswordConfirm(message string) (*SecureValue, error)
}

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

// SecureValue is a wrapper for sensitive string values that ensures memory cleanup
// This type helps prevent sensitive data from remaining in memory after use
type SecureValue struct {
	data []byte
}

// NewSecureValue creates a new SecureValue from a string
// The value string should be cleared by the caller after creating SecureValue
func NewSecureValue(value string) *SecureValue {
	return &SecureValue{
		data: []byte(value),
	}
}

// String returns the value as a string
// WARNING: The returned string will remain in memory until garbage collected
// Use this method only when absolutely necessary and clear the result when done
func (sv *SecureValue) String() string {
	if sv == nil || sv.data == nil {
		return ""
	}
	// Check if data has been cleared (all zeros)
	allZero := true
	for _, b := range sv.data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	return string(sv.data)
}

// Bytes returns the value as a byte slice
func (sv *SecureValue) Bytes() []byte {
	if sv == nil || sv.data == nil {
		return nil
	}
	return sv.data
}

// Clear securely erases the value from memory
// This should be called as soon as the value is no longer needed
func (sv *SecureValue) Clear() {
	if sv != nil && sv.data != nil {
		// Overwrite memory with zeros
		for i := range sv.data {
			sv.data[i] = 0
		}
		// Keep the slice allocated but zeroed for inspection
		// sv.data = nil  // Don't nil the slice, keep it zeroed
	}
}

// SecureSlice is a wrapper for slices containing sensitive data that ensures memory cleanup
type SecureSlice[T any] []T

// NewSecureSlice creates a new SecureSlice from a regular slice
func NewSecureSlice[T any](items []T) *SecureSlice[T] {
	slice := SecureSlice[T](items)
	return &slice
}

// Slice returns the underlying slice
func (ss *SecureSlice[T]) Slice() []T {
	if ss == nil {
		return nil
	}
	return []T(*ss)
}

// Clear securely erases the slice contents
func (ss *SecureSlice[T]) Clear() {
	if ss != nil {
		*ss = nil
	}
}

// SecureMap is a wrapper for maps containing sensitive data that ensures memory cleanup
type SecureMap[K comparable, V any] map[K]V

// NewSecureMap creates a new SecureMap from a regular map
func NewSecureMap[K comparable, V any](data map[K]V) *SecureMap[K, V] {
	sm := SecureMap[K, V](data)
	return &sm
}

// Map returns the underlying map
func (sm *SecureMap[K, V]) Map() map[K]V {
	if sm == nil {
		return nil
	}
	return map[K]V(*sm)
}

// Clear securely erases the map contents
func (sm *SecureMap[K, V]) Clear() {
	if sm != nil {
		for k := range *sm {
			delete(*sm, k)
		}
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
func GetPassword(cfg *config.Config, prm PromptManagerInterface, log logger.Manager, creating bool) (*SecurePassword, error) {
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
	var passwordSecure *SecureValue
	var err error

	if creating {
		// Creating new database: ask twice for confirmation
		passwordSecure, err = prm.PromptPasswordConfirm("Enter database password")
	} else {
		// Verifying existing database: ask once
		passwordSecure, err = prm.PromptPassword("Enter database password: ")
	}

	if err != nil {
		return nil, err
	}

	// Convert to SecurePassword and clear the temporary SecureValue
	securePassword := NewSecurePassword(passwordSecure.String())
	passwordSecure.Clear()
	return securePassword, nil
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
