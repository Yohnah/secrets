// Package keepass provides factory functions for creating KeePass instances
package keepass

import "github.com/Yohnah/secrets/internal/secrets"

// Factory provides factory methods for creating SecretsManager instances
// This follows the Factory Pattern and Open/Closed Principle (OCP)
type Factory struct{}

// NewFactory creates a new Factory instance
func NewFactory() *Factory {
	return &Factory{}
}

// CreateKeePass creates a KeePass instance with default implementations
// This is the convenience method for normal use
func (f *Factory) CreateKeePass(dbPath string) (secrets.SecretsManager, error) {
	return New(dbPath)
}

// CreateKeePassWithHandlers creates a KeePass with custom handlers
// This method allows full dependency injection for testing and customization (DIP)
func (f *Factory) CreateKeePassWithHandlers(
	dbPath string,
	pathHandler secrets.PathHandler,
	authHandler secrets.AuthHandler,
	dataHandler secrets.DataHandler) (secrets.SecretsManager, error) {
	
	return NewWithDependencies(dbPath, pathHandler, authHandler, dataHandler)
}

// DefaultHandlers creates the default set of handlers
// This allows easy creation of default implementations
func (f *Factory) DefaultHandlers() (secrets.PathHandler, secrets.AuthHandler, secrets.DataHandler) {
	return NewPathHandler(), NewAuthHandler(), NewDataHandler()
}