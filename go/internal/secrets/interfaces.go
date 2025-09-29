// Package secrets defines core interfaces following Interface Segregation Principle (ISP)
package secrets

// SecretsManager - Main interface that clients use
type SecretsManager interface {
	// Connection operations
	CreateDB(username, password string, createKeyFile bool) error
	Open(username, password, keyFilePath string) error
	Close()
	IsOpen() bool
	Save() error
	GetKeyFilePath() string

	// Data operations (includes payload for future Vault integration)
	Get(entryPath string, key *string, payload map[string]interface{}) (interface{}, error)
	Write(entryPath, key string, value interface{}, isFile bool) error
	Delete(entryPath string, key *string) error
	List() ([]string, error)
}

// Small, focused interfaces for dependency injection (DIP)

// PathHandler handles path operations (SRP)
type PathHandler interface {
	ValidatePath(path string) error
	NormalizePath(path string) string
	SplitPath(path string) []string
	GetKeyFilePath(dbPath string) string
}

// AuthHandler manages authentication (SRP)
type AuthHandler interface {
	CreateCredentials(password string, keyData []byte) interface{}
	GenerateKeyFile() ([]byte, error)
	LoadKeyFile(path string) ([]byte, error)
}

// DataHandler manages entry operations (SRP)
type DataHandler interface {
	FindEntry(db interface{}, entryPath string) (interface{}, error)
	CreateEntry(db interface{}, entryPath string) (interface{}, error)
	SaveDatabase(db interface{}, path string) error
}