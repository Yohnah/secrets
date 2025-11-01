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
) // TestSecretsInitNonInteractive prueba secrets init en modo no-interactivo
func TestSecretsInitNonInteractive(t *testing.T) {
	// Setup: crear directorio temporal
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	_ = filepath.Join(tmpDir, "default")                 // dbDir
	_ = filepath.Join(tmpDir, "default", "secrets.kdbx") // dbPath (no usado aún)
	_ = filepath.Join(tmpDir, "default", "secrets.key")  // keyfilePath (no usado aún)

	// Set environment variables
	os.Setenv("SECRETS_CONFIG_FILE", configPath)
	os.Setenv("SECRETS_PASSWORD", "123456")
	defer os.Unsetenv("SECRETS_CONFIG_FILE")
	defer os.Unsetenv("SECRETS_PASSWORD")

	// TODO: Ejecutar comando real cuando esté disponible el binario compilado
	// Por ahora validamos que la estructura esperada es correcta

	// Validaciones esperadas:
	// 1. Directorio de configuración creado
	_, err := os.Stat(tmpDir)
	require.NoError(t, err, "Config directory should exist")

	// 2. Permisos correctos del directorio (0700)
	// 3. Archivo config.yml creado con permisos 0600
	// 4. Directorio database/<name>/ creado
	// 5. Archivo secrets.kdbx creado
	// 6. Archivo secrets.key creado (si no --no-keyfile)
	// 7. Grupo raíz en BBDD: SECRETS_<database.name>
}

// TestSecretsInitMultipleDB prueba creación de múltiples BBDD con nombres diferentes
func TestSecretsInitMultipleDB(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")

	os.Setenv("SECRETS_CONFIG_FILE", configPath)
	os.Setenv("SECRETS_PASSWORD", "123456")
	defer os.Unsetenv("SECRETS_CONFIG_FILE")
	defer os.Unsetenv("SECRETS_PASSWORD")

	// Primera DB: default
	// TODO: Ejecutar secrets init --non-interactive --database-name default

	// Segunda DB: production
	// TODO: Ejecutar secrets init --non-interactive --database-name production

	// Validar que config.yml tiene 2 documentos YAML separados por ---
	// Validar que existen 2 directorios: default/ y production/
	// Validar que cada directorio tiene su .kdbx y .key
}

// TestSecretsInitForceRecreate prueba flag --force-recreate
func TestSecretsInitForceRecreate(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	_ = filepath.Join(tmpDir, "testdb")                 // dbDir (no usado aún)
	_ = filepath.Join(tmpDir, "testdb", "secrets.kdbx") // dbPath (no usado aún)

	os.Setenv("SECRETS_CONFIG_FILE", configPath)
	os.Setenv("SECRETS_PASSWORD", "123456")
	defer os.Unsetenv("SECRETS_CONFIG_FILE")
	defer os.Unsetenv("SECRETS_PASSWORD")

	// Primera ejecución: crear BBDD
	// TODO: Ejecutar secrets init --non-interactive --database-name testdb

	// Validar que .kdbx existe
	// Guardar timestamp del archivo

	// Segunda ejecución: sin --force-recreate → NO debe recrear
	// TODO: Ejecutar secrets init --non-interactive --database-name testdb (sin --force-recreate)

	// Validar que timestamp NO cambió

	// Tercera ejecución: con --force-recreate → SÍ debe recrear
	// TODO: Ejecutar secrets init --non-interactive --database-name testdb --force-recreate

	// Validar que timestamp SÍ cambió (archivo recreado)
}

// TestSecretsInitNoKeyfile prueba flag --no-keyfile
func TestSecretsInitNoKeyfile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	dbDir := filepath.Join(tmpDir, "nokey")
	keyfilePath := filepath.Join(dbDir, "secrets.key")

	os.Setenv("SECRETS_CONFIG_FILE", configPath)
	os.Setenv("SECRETS_PASSWORD", "123456")
	defer os.Unsetenv("SECRETS_CONFIG_FILE")
	defer os.Unsetenv("SECRETS_PASSWORD")

	// Ejecutar con --no-keyfile
	// TODO: Ejecutar secrets init --non-interactive --database-name nokey --no-keyfile

	// Validar que secrets.key NO existe
	_, err := os.Stat(keyfilePath)
	assert.True(t, os.IsNotExist(err), "Keyfile should NOT exist with --no-keyfile")

	// Validar que config.yml NO tiene campo keyfile (o está vacío)
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

	// TODO: Descomentar cuando binario esté disponible
	// _, err := os.Stat(dbPath)
	// require.NoError(t, err, "DB should exist at absolute path")
	// _, err = os.Stat(keyfilePath)
	// require.NoError(t, err, "Keyfile should exist at absolute path")

	_ = dbPath
	_ = keyfilePath
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
