package bdmanager

import (
"github.com/Yohnah/secrets/internal/bdmanager/keepassadapter"
"github.com/Yohnah/secrets/internal/loggermanager"
"github.com/Yohnah/secrets/internal/validatormanager"
)

// BD interface defines the database management contract
type BD interface {
DatabaseExists(path string) bool
GenerateKeyfile(path string) error
CreateDatabase(dbPath, password, keyfilePath, dbName string) error
DeleteDatabase(path string) error
}

// StandardBD implements BD with KeePass support
type StandardBD struct {
logger         loggermanager.Logger
validator      validatormanager.Validator
keepassAdapter keepassadapter.KeePassAdapter
}

// NewStandardBD creates a new database manager
func NewStandardBD(logger loggermanager.Logger, validator validatormanager.Validator) BD {
return &StandardBD{
logger:         logger,
validator:      validator,
keepassAdapter: keepassadapter.NewKeePassAdapter(logger),
}
}

// DatabaseExists checks if database file exists
func (b *StandardBD) DatabaseExists(path string) bool {
return b.keepassAdapter.DatabaseExists(path)
}

// GenerateKeyfile generates a new keyfile for database encryption
func (b *StandardBD) GenerateKeyfile(path string) error {
return b.keepassAdapter.GenerateKeyfile(path)
}

// CreateDatabase creates a new KeePass database
func (b *StandardBD) CreateDatabase(dbPath, password, keyfilePath, dbName string) error {
return b.keepassAdapter.CreateDatabase(dbPath, password, keyfilePath, dbName)
}

// DeleteDatabase deletes a database file
func (b *StandardBD) DeleteDatabase(path string) error {
return b.keepassAdapter.DeleteDatabase(path)
}
