package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/validator"
)

// PromptManagerInterface defines the interface for prompting user input
type PromptManagerInterface interface {
	PromptPassword(message string) (*SecureValue, error)
	PromptPasswordConfirm(message string) (*SecureValue, error)
}

// PasswordProvider defines the interface for obtaining passwords
type PasswordProvider interface {
	GetPassword() (string, error)
	IsNoInteractive() bool
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
	data        []byte
	encrypted   []byte
	isEncrypted bool
	key         []byte
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
	if sv == nil {
		return ""
	}

	// If encrypted, decrypt first
	if sv.isEncrypted && sv.encrypted != nil {
		decrypted, err := sv.decrypt()
		if err != nil {
			return ""
		}
		return string(decrypted)
	}

	if sv.data == nil {
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

// Bytes returns a copy of the value as a byte slice
func (sv *SecureValue) Bytes() []byte {
	if sv == nil {
		return nil
	}

	// If encrypted, decrypt first
	if sv.isEncrypted && sv.encrypted != nil {
		decrypted, err := sv.decrypt()
		if err != nil {
			return nil
		}
		return decrypted
	}

	if sv.data == nil {
		return nil
	}
	// Return a copy to prevent external modifications
	cpy := make([]byte, len(sv.data))
	copy(cpy, sv.data)
	return cpy
}

// Clear securely erases the value from memory
// This should be called as soon as the value is no longer needed
func (sv *SecureValue) Clear() {
	if sv != nil {
		if sv.data != nil {
			// Overwrite memory with zeros
			for i := range sv.data {
				sv.data[i] = 0
			}
			sv.data = nil
		}
		if sv.encrypted != nil {
			// Overwrite encrypted data with zeros
			for i := range sv.encrypted {
				sv.encrypted[i] = 0
			}
			sv.encrypted = nil
		}
		if sv.key != nil {
			// Overwrite key with zeros
			for i := range sv.key {
				sv.key[i] = 0
			}
			sv.key = nil
		}
		sv.isEncrypted = false
	}
}

// Encrypt encrypts the SecureValue data using AES-GCM with a derived key
func (sv *SecureValue) Encrypt(password string) error {
	if sv == nil || sv.data == nil || sv.isEncrypted {
		return nil // Already encrypted or no data
	}

	// Derive key from password using SHA-256
	hash := sha256.Sum256([]byte(password))
	key := hash[:]

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	encrypted := gcm.Seal(nonce, nonce, sv.data, nil)

	// Store encrypted data and key
	sv.encrypted = make([]byte, len(encrypted))
	copy(sv.encrypted, encrypted)
	sv.key = make([]byte, len(key))
	copy(sv.key, key)
	sv.isEncrypted = true

	// Clear plaintext data
	for i := range sv.data {
		sv.data[i] = 0
	}
	sv.data = nil

	return nil
}

// decrypt decrypts the SecureValue data
func (sv *SecureValue) decrypt() ([]byte, error) {
	if !sv.isEncrypted || sv.encrypted == nil || sv.key == nil {
		return nil, fmt.Errorf("data is not encrypted")
	}

	// Create AES cipher
	block, err := aes.NewCipher(sv.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(sv.encrypted) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Extract nonce and ciphertext
	nonce := sv.encrypted[:nonceSize]
	ciphertext := sv.encrypted[nonceSize:]

	// Decrypt data
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return decrypted, nil
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

// GetPassword obtains a password from various sources with proper security handling
//
// Parameters:
//   - provider: PasswordProvider interface for obtaining passwords
//   - prm: PromptManagerInterface for user interaction
//   - log: LoggerManager for logging operations
//   - creating: Whether this is for database creation (affects messaging)
//
// Returns:
//   - *SecurePassword: Password wrapped in secure container (caller must call Clear() when done)
//   - error: Error if password cannot be obtained
//
// Security: The returned SecurePassword must be cleared after use by calling Clear()
// to prevent password from remaining in memory
func GetPassword(provider interface {
	GetPassword() (string, error)
	IsNoInteractive() bool
}, prm PromptManagerInterface, log logger.Manager, creating bool) (*SecurePassword, error) {
	// Try to get password from provider (env var, etc.)
	password, err := provider.GetPassword()
	if err == nil && password != "" {
		log.Debug("Using password from configuration (SECRETS_YOHNAH_PASSWORD environment variable)")
		return NewSecurePassword(password), nil
	}

	// If in non-interactive mode and no password provided, fail
	if provider.IsNoInteractive() {
		return nil, fmt.Errorf("password required. Set SECRETS_YOHNAH_PASSWORD environment variable or remove -f flag")
	}

	// Prompt user for password
	var promptedPassword *SecureValue
	var promptErr error

	if creating {
		// Creating new database: ask twice for confirmation
		promptedPassword, promptErr = prm.PromptPasswordConfirm("Enter database password")
	} else {
		// Verifying existing database: ask once
		promptedPassword, promptErr = prm.PromptPassword("Enter database password: ")
	}

	if promptErr != nil {
		return nil, promptErr
	}

	// Convert to SecurePassword and clear the temporary SecureValue
	securePassword := NewSecurePassword(promptedPassword.String())
	promptedPassword.Clear()
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
