package bdmanager

import (
"github.com/Yohnah/secrets/internal/bdmanager/keepassadapter"
"github.com/Yohnah/secrets/internal/loggermanager"
"github.com/Yohnah/secrets/internal/validatormanager"
)

type BD interface {
DatabaseExists(path string) bool
GenerateKeyfile(path string) error
CreateDatabase(dbPath, password, keyfilePath, dbName string) error
DeleteDatabase(path string) error
}

type StandardBD struct {
logger         loggermanager.Logger
validator      validatormanager.Validator
keepassAdapter keepassadapter.KeePassAdapter
}

func NewStandardBD(logger loggermanager.Logger, validator validatormanager.Validator) BD {
return &StandardBD{
logger:         logger,
validator:      validator,
keepassAdapter: keepassadapter.NewKeePassAdapter(logger),
}
}

func (b *StandardBD) DatabaseExists(path string) bool {
return b.keepassAdapter.DatabaseExists(path)
}

func (b *StandardBD) GenerateKeyfile(path string) error {
return b.keepassAdapter.GenerateKeyfile(path)
}

func (b *StandardBD) CreateDatabase(dbPath, password, keyfilePath, dbName string) error {
return b.keepassAdapter.CreateDatabase(dbPath, password, keyfilePath, dbName)
}

func (b *StandardBD) DeleteDatabase(path string) error {
return b.keepassAdapter.DeleteDatabase(path)
}
