package keepassadapter

import (
"crypto/rand"
"fmt"
"os"
"strings"

"github.com/Yohnah/secrets/internal/loggermanager"
"github.com/tobischo/gokeepasslib/v3"
)

type KeePassAdapter interface {
DatabaseExists(path string) bool
GenerateKeyfile(path string) error
CreateDatabase(dbPath, password, keyfilePath, dbName string) error
DeleteDatabase(path string) error
}

type StandardKeePassAdapter struct {
logger loggermanager.Logger
}

func NewKeePassAdapter(logger loggermanager.Logger) KeePassAdapter {
return &StandardKeePassAdapter{logger: logger}
}

func (k *StandardKeePassAdapter) DatabaseExists(path string) bool {
_, err := os.Stat(path)
return err == nil
}

func (k *StandardKeePassAdapter) GenerateKeyfile(path string) error {
keyData := make([]byte, 64)
if _, err := rand.Read(keyData); err != nil {
return fmt.Errorf("failed to generate random key: %w", err)
}
if err := os.WriteFile(path, keyData, 0600); err != nil {
return fmt.Errorf("failed to write keyfile: %w", err)
}
k.logger.Debug(fmt.Sprintf("Generated keyfile: %s", path))
return nil
}

func (k *StandardKeePassAdapter) CreateDatabase(dbPath, password, keyfilePath, dbName string) error {
db := gokeepasslib.NewDatabase()
db.Options = gokeepasslib.NewOptions()
if password == "" {
return fmt.Errorf("password cannot be empty")
}
credentials := &gokeepasslib.DBCredentials{Passphrase: []byte(password)}
if keyfilePath != "" {
keyData, err := os.ReadFile(keyfilePath)
if err != nil {
return fmt.Errorf("failed to read keyfile: %w", err)
}
credentials.Key = keyData
}
db.Credentials = credentials
rootGroupName := fmt.Sprintf("SECRETS_%s", strings.ToUpper(dbName))
rootGroup := gokeepasslib.NewGroup()
rootGroup.Name = rootGroupName
db.Content.Root.Groups = append(db.Content.Root.Groups, rootGroup)
if err := db.LockProtectedEntries(); err != nil {
return fmt.Errorf("failed to lock protected entries: %w", err)
}
file, err := os.Create(dbPath)
if err != nil {
return fmt.Errorf("failed to create database file: %w", err)
}
defer file.Close()
encoder := gokeepasslib.NewEncoder(file)
if err := encoder.Encode(db); err != nil {
return fmt.Errorf("failed to encode database: %w", err)
}
k.logger.Debug(fmt.Sprintf("Created KeePass database: %s (root group: %s)", dbPath, rootGroupName))
return nil
}

func (k *StandardKeePassAdapter) DeleteDatabase(path string) error {
if err := os.Remove(path); err != nil {
return fmt.Errorf("failed to delete database: %w", err)
}
k.logger.Debug(fmt.Sprintf("Deleted database: %s", path))
return nil
}
