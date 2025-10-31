package envvars

import "os"

// EnvVarsReader interface defines the contract for reading environment variables
type EnvVarsReader interface {
	Get(key string) (string, bool)
}

// OsEnvVarsReader implements EnvVarsReader using os.LookupEnv
type OsEnvVarsReader struct{}

// NewOsEnvVarsReader creates a new environment variables reader
func NewOsEnvVarsReader() EnvVarsReader {
	return &OsEnvVarsReader{}
}

// Get retrieves an environment variable value
func (r *OsEnvVarsReader) Get(key string) (string, bool) {
	return os.LookupEnv(key)
}
