package keepass

import (
	"crypto/rand"
	"os"

	"github.com/Yohnah/secrets/internal/secrets"
)

// AuthHandler handles authentication operations (SRP - Single Responsibility)
type AuthHandler struct{}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler() secrets.AuthHandler {
	return &AuthHandler{}
}

// CreateCredentials creates mock credentials (simplified for SOLID demo)
func (a *AuthHandler) CreateCredentials(password string, keyData []byte) interface{} {
	return map[string]interface{}{
		"password": password,
		"keyfile":  keyData != nil,
	}
}

// GenerateKeyFile generates a secure keyfile
func (a *AuthHandler) GenerateKeyFile() ([]byte, error) {
	keyData := make([]byte, 32)
	_, err := rand.Read(keyData)
	return keyData, err
}

// LoadKeyFile loads a keyfile from disk
func (a *AuthHandler) LoadKeyFile(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	return os.ReadFile(path)
}