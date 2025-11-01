package integration

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
) // TestSecretsInitNonInteractive tests secrets init in non-interactive mode
func TestSecretsInitNonInteractive(t *testing.T) {
	// Setup: create temporary directory
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	dbDir := filepath.Join(tmpDir, "default")
	dbPath := filepath.Join(dbDir, "secrets.kdbx")
	keyfilePath := filepath.Join(dbDir, "secrets.key")

	// Set environment variables
	os.Setenv("SECRETS_CONFIG_FILE", configPath)
	os.Setenv("SECRETS_PASSWORD", "123456")
	defer os.Unsetenv("SECRETS_CONFIG_FILE")
	defer os.Unsetenv("SECRETS_PASSWORD")

	// TODO: Execute real command when binary is available
	// For now we validate that the expected structure is correct

	// Expected validations:
	// 1. Config directory created
	_, err := os.Stat(tmpDir)
	require.NoError(t, err, "Config directory should exist")

	// 2. Correct directory permissions (0700)
	// 3. config.yml file created with 0600 permissions
	// 4. database/<name>/ directory created
	// 5. secrets.kdbx file created
	// 6. secrets.key file created (if not --no-keyfile)
	// 7. Root group in DB: SECRETS_<database.name>
}

// TestSecretsInitMultipleDB tests creation of multiple DBs with different names
func TestSecretsInitMultipleDB(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")

	os.Setenv("SECRETS_CONFIG_FILE", configPath)
	os.Setenv("SECRETS_PASSWORD", "123456")
	defer os.Unsetenv("SECRETS_CONFIG_FILE")
	defer os.Unsetenv("SECRETS_PASSWORD")

	// First DB: default
	// TODO: Execute secrets init --non-interactive --database-name default

	// Second DB: production
	// TODO: Execute secrets init --non-interactive --database-name production

	// Validate that config.yml has 2 YAML documents separated by ---
	// Validate that 2 directories exist: default/ and production/
	// Validate that each directory has its .kdbx and .key
}

// TestSecretsInitForceRecreate tests --force-recreate flag
func TestSecretsInitForceRecreate(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	dbDir := filepath.Join(tmpDir, "testdb")
	dbPath := filepath.Join(dbDir, "secrets.kdbx")

	os.Setenv("SECRETS_CONFIG_FILE", configPath)
	os.Setenv("SECRETS_PASSWORD", "123456")
	defer os.Unsetenv("SECRETS_CONFIG_FILE")
	defer os.Unsetenv("SECRETS_PASSWORD")

	// First execution: create DB
	// TODO: Execute secrets init --non-interactive --database-name testdb

	// Validate that .kdbx exists
	// Save file timestamp

	// Second execution: without --force-recreate → should NOT recreate
	// TODO: Execute secrets init --non-interactive --database-name testdb (without --force-recreate)

	// Validate that timestamp did NOT change

	// Third execution: with --force-recreate → should recreate
	// TODO: Execute secrets init --non-interactive --database-name testdb --force-recreate

	// Validate that timestamp DID change (file recreated)
}

// TestSecretsInitNoKeyfile tests --no-keyfile flag
func TestSecretsInitNoKeyfile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	dbDir := filepath.Join(tmpDir, "nokey")
	keyfilePath := filepath.Join(dbDir, "secrets.key")

	os.Setenv("SECRETS_CONFIG_FILE", configPath)
	os.Setenv("SECRETS_PASSWORD", "123456")
	defer os.Unsetenv("SECRETS_CONFIG_FILE")
	defer os.Unsetenv("SECRETS_PASSWORD")

	// Execute with --no-keyfile
	// TODO: Execute secrets init --non-interactive --database-name nokey --no-keyfile

	// Validate that secrets.key does NOT exist
	_, err := os.Stat(keyfilePath)
	assert.True(t, os.IsNotExist(err), "Keyfile should NOT exist with --no-keyfile")

	// Validate that config.yml does NOT have keyfile field (or is empty)
}

// TestSecretsInitWithAbsolutePaths prueba rutas absolutas para database y keyfile
func TestSecretsInitWithAbsolutePaths(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	dbPath := filepath.Join(tmpDir, "custom", "db.kdbx")
	keyfilePath := filepath.Join(tmpDir, "custom", "db.key")

	os.Setenv("SECRETS_CONFIG_FILE", configPath)
	os.Setenv("SECRETS_PASSWORD", "123456")
	defer os.Unsetenv("SECRETS_CONFIG_FILE")
	defer os.Unsetenv("SECRETS_PASSWORD")

	// Ejecutar con rutas absolutas
	// TODO: Ejecutar secrets init --non-interactive \
	//   --database-name custom \
	//   --database-path <dbPath> \
	//   --keyfile <keyfilePath>

	// Validar que NO se crea subdirectorio $HOME/.secrets/custom/
	// Validar que archivos están en rutas absolutas especificadas
	_, err := os.Stat(dbPath)
	require.NoError(t, err, "DB should exist at absolute path")

	_, err = os.Stat(keyfilePath)
	require.NoError(t, err, "Keyfile should exist at absolute path")
}

// TestSecretsInitConfigYAMLFormat valida formato del config.yml generado
func TestSecretsInitConfigYAMLFormat(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")

	// Crear manualmente un config.yml de prueba
	configData := `database:
  name: "default"
  path: "secrets.kdbx"
  keyfile: "secrets.key"
---
database:
  name: "production"
  path: "/secure/prod.kdbx"
  keyfile: "/secure/prod.key"`

	err := os.WriteFile(configPath, []byte(configData), 0600)
	require.NoError(t, err)

	// Leer y parsear YAML multi-documento
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)

	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	var configs []map[string]interface{}

	for {
		var config map[string]interface{}
		err := decoder.Decode(&config)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		configs = append(configs, config)
	}

	// Validar que hay 2 documentos
	assert.Equal(t, 2, len(configs), "Should have 2 YAML documents")

	// Validar estructura primer documento
	db1 := configs[0]["database"].(map[string]interface{})
	assert.Equal(t, "default", db1["name"])
	assert.Equal(t, "secrets.kdbx", db1["path"])
	assert.Equal(t, "secrets.key", db1["keyfile"])

	// Validar estructura segundo documento
	db2 := configs[1]["database"].(map[string]interface{})
	assert.Equal(t, "production", db2["name"])
	assert.Equal(t, "/secure/prod.kdbx", db2["path"])
	assert.Equal(t, "/secure/prod.key", db2["keyfile"])
}
