package secrets_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/secrets/importer"
	"github.com/Yohnah/secrets/internal/validator"
)

// TestParseFile_DetectsJSONFormat tests that JSON format is correctly detected
func TestParseFile_DetectsJSONFormat(t *testing.T) {
	tempDir := t.TempDir()
	jsonFilePath := filepath.Join(tempDir, "test.json")

	content := `{"key": "value", "number": 123}`
	if err := os.WriteFile(jsonFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	vars, err := importer.ParseFile(jsonFilePath, false)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if vars["key"] != "value" {
		t.Errorf("Expected key='value', got '%s'", vars["key"])
	}
}

// TestParseFile_DetectsYAMLFormat tests that YAML format is correctly detected
func TestParseFile_DetectsYAMLFormat(t *testing.T) {
	tempDir := t.TempDir()
	yamlFilePath := filepath.Join(tempDir, "test.yml")

	content := `key: value
nested:
  subkey: subvalue`
	if err := os.WriteFile(yamlFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	vars, err := importer.ParseFile(yamlFilePath, false)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if vars["key"] != "value" {
		t.Errorf("Expected key='value', got '%s'", vars["key"])
	}
	// Nested should be flattened as nested.subkey
	if vars["nested.subkey"] != "subvalue" {
		t.Errorf("Expected nested.subkey='subvalue', got '%s'", vars["nested.subkey"])
	}
}

// TestParseFile_DetectsDotenvFormat tests that .env format is correctly detected
func TestParseFile_DetectsDotenvFormat(t *testing.T) {
	tempDir := t.TempDir()
	envFilePath := filepath.Join(tempDir, "test.env")

	content := `KEY=value
DATABASE_URL=postgres://localhost:5432/db`
	if err := os.WriteFile(envFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	vars, err := importer.ParseFile(envFilePath, false)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if vars["KEY"] != "value" {
		t.Errorf("Expected KEY='value', got '%s'", vars["KEY"])
	}
	if vars["DATABASE_URL"] != "postgres://localhost:5432/db" {
		t.Errorf("Expected DATABASE_URL='postgres://localhost:5432/db', got '%s'", vars["DATABASE_URL"])
	}
}

// TestParseFile_DetectsPropertiesFormat tests that .properties format is correctly detected
func TestParseFile_DetectsPropertiesFormat(t *testing.T) {
	tempDir := t.TempDir()
	propsFilePath := filepath.Join(tempDir, "test.properties")

	content := `app.name=MyApp
app.version=1.0.0`
	if err := os.WriteFile(propsFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	vars, err := importer.ParseFile(propsFilePath, false)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if vars["app.name"] != "MyApp" {
		t.Errorf("Expected app.name='MyApp', got '%s'", vars["app.name"])
	}
	if vars["app.version"] != "1.0.0" {
		t.Errorf("Expected app.version='1.0.0', got '%s'", vars["app.version"])
	}
}

// TestParseFile_DetectsTOMLFormat tests that .toml format is correctly detected
func TestParseFile_DetectsTOMLFormat(t *testing.T) {
	tempDir := t.TempDir()
	tomlFilePath := filepath.Join(tempDir, "test.toml")

	content := `title = "TOML Example"

[database]
server = "192.168.1.1"
port = 5432`
	if err := os.WriteFile(tomlFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	vars, err := importer.ParseFile(tomlFilePath, false)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if vars["title"] != "TOML Example" {
		t.Errorf("Expected title='TOML Example', got '%s'", vars["title"])
	}
	if vars["database.server"] != "192.168.1.1" {
		t.Errorf("Expected database.server='192.168.1.1', got '%s'", vars["database.server"])
	}
}

// TestParseFile_DetectsTerraformFormat tests that .tfvars format is correctly detected
func TestParseFile_DetectsTerraformFormat(t *testing.T) {
	tempDir := t.TempDir()
	tfvarsFilePath := filepath.Join(tempDir, "test.tfvars")

	content := `region = "us-west-2"
instance_type = "t2.micro"`
	if err := os.WriteFile(tfvarsFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	vars, err := importer.ParseFile(tfvarsFilePath, false)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if vars["region"] != "us-west-2" {
		t.Errorf("Expected region='us-west-2', got '%s'", vars["region"])
	}
	if vars["instance_type"] != "t2.micro" {
		t.Errorf("Expected instance_type='t2.micro', got '%s'", vars["instance_type"])
	}
}

// TestParseFile_DetectsINIFormat tests that .ini format is correctly detected
func TestParseFile_DetectsINIFormat(t *testing.T) {
	tempDir := t.TempDir()
	iniFilePath := filepath.Join(tempDir, "test.ini")

	content := `[section1]
key1=value1
key2=value2

[section2]
key3=value3`
	if err := os.WriteFile(iniFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	vars, err := importer.ParseFile(iniFilePath, false)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if vars["section1.key1"] != "value1" {
		t.Errorf("Expected section1.key1='value1', got '%s'", vars["section1.key1"])
	}
	if vars["section2.key3"] != "value3" {
		t.Errorf("Expected section2.key3='value3', got '%s'", vars["section2.key3"])
	}
}

// TestParseFile_KubernetesSecretDetection tests that Kubernetes Secrets values are stored as-is
func TestParseFile_KubernetesSecretDetection(t *testing.T) {
	tempDir := t.TempDir()
	k8sFilePath := filepath.Join(tempDir, "k8s-secret.yml")

	// Kubernetes Secret without automatic decoding
	content := `apiVersion: v1
kind: Secret
metadata:
  name: mysecret
type: Opaque
data:
  username: YWRtaW4=
  password: MWYyZDFlMmU2N2Rm`
	if err := os.WriteFile(k8sFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Without --decode-base64 flag, values should be stored as-is
	vars, err := importer.ParseFile(k8sFilePath, false)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// Should have base64 encoded values (as-is from file)
	if vars["username"] != "YWRtaW4=" {
		t.Errorf("Expected username='YWRtaW4=' (as-is), got '%s'", vars["username"])
	}
	if vars["password"] != "MWYyZDFlMmU2N2Rm" {
		t.Errorf("Expected password='MWYyZDFlMmU2N2Rm' (as-is), got '%s'", vars["password"])
	}
}

// TestParseFile_Base64Decoding tests that base64 decoding works with --decode-base64
func TestParseFile_Base64Decoding(t *testing.T) {
	tempDir := t.TempDir()
	jsonFilePath := filepath.Join(tempDir, "test.json")

	// "admin" in base64 is "YWRtaW4="
	// "1f2d1e2e67df" in base64 is "MWYyZDFlMmU2N2Rm"
	content := `{"username": "YWRtaW4=", "password": "MWYyZDFlMmU2N2Rm"}`
	if err := os.WriteFile(jsonFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	vars, err := importer.ParseFile(jsonFilePath, true)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if vars["username"] != "admin" {
		t.Errorf("Expected username='admin' (decoded), got '%s'", vars["username"])
	}
	if vars["password"] != "1f2d1e2e67df" {
		t.Errorf("Expected password='1f2d1e2e67df' (decoded), got '%s'", vars["password"])
	}
}

// TestParseFile_KubernetesSecretWithBase64Decoding tests K8s secret with explicit decoding flag
func TestParseFile_KubernetesSecretWithBase64Decoding(t *testing.T) {
	tempDir := t.TempDir()
	k8sFilePath := filepath.Join(tempDir, "k8s-secret.yml")

	content := `apiVersion: v1
kind: Secret
metadata:
  name: mysecret
type: Opaque
data:
  username: YWRtaW4=
  password: MWYyZDFlMmU2N2Rm`
	if err := os.WriteFile(k8sFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// With --decode-base64 flag, values should be decoded
	vars, err := importer.ParseFile(k8sFilePath, true)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// Should be decoded when using --decode-base64 flag
	if vars["username"] != "admin" {
		t.Errorf("Expected username='admin' (decoded), got '%s'", vars["username"])
	}
	if vars["password"] != "1f2d1e2e67df" {
		t.Errorf("Expected password='1f2d1e2e67df' (decoded), got '%s'", vars["password"])
	}
}

// TestParseFile_KubernetesSecretWithPlainText tests K8s secret with plain text values (not base64)
func TestParseFile_KubernetesSecretWithPlainText(t *testing.T) {
	tempDir := t.TempDir()
	k8sFilePath := filepath.Join(tempDir, "k8s-secret.yml")

	content := `apiVersion: v1
kind: Secret
metadata:
  name: mysecret
type: Opaque
data:
  plain1: jajajaja
  plain2: jejejeje
  encoded1: YWRtaW4=
  encoded2: cGFzc3dvcmQxMjM=`
	if err := os.WriteFile(k8sFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Without --decode-base64 flag, all values stored as-is
	vars, err := importer.ParseFile(k8sFilePath, false)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// All values should remain as-is
	if vars["plain1"] != "jajajaja" {
		t.Errorf("Expected plain1='jajajaja', got '%s'", vars["plain1"])
	}
	if vars["plain2"] != "jejejeje" {
		t.Errorf("Expected plain2='jejejeje', got '%s'", vars["plain2"])
	}
	if vars["encoded1"] != "YWRtaW4=" {
		t.Errorf("Expected encoded1='YWRtaW4=' (as-is), got '%s'", vars["encoded1"])
	}
	if vars["encoded2"] != "cGFzc3dvcmQxMjM=" {
		t.Errorf("Expected encoded2='cGFzc3dvcmQxMjM=' (as-is), got '%s'", vars["encoded2"])
	}

	// With --decode-base64 flag, all values are decoded
	varsDecoded, err := importer.ParseFile(k8sFilePath, true)
	if err != nil {
		t.Fatalf("ParseFile with decode failed: %v", err)
	}

	// All values should be decoded (even if result is garbage for non-base64)
	if varsDecoded["encoded1"] != "admin" {
		t.Errorf("Expected encoded1='admin' (decoded), got '%s'", varsDecoded["encoded1"])
	}
	if varsDecoded["encoded2"] != "password123" {
		t.Errorf("Expected encoded2='password123' (decoded), got '%s'", varsDecoded["encoded2"])
	}
}

// TestParseFile_FileNotFound tests error when file doesn't exist
func TestParseFile_FileNotFound(t *testing.T) {
	_, err := importer.ParseFile("/nonexistent/file.json", false)
	if err == nil {
		t.Fatal("Expected error for non-existent file, got nil")
	}
}

// TestParseFile_InvalidJSONFormat tests error handling for invalid JSON
func TestParseFile_InvalidJSONFormat(t *testing.T) {
	tempDir := t.TempDir()
	jsonFilePath := filepath.Join(tempDir, "invalid.json")

	content := `{"key": "value", invalid json}`
	if err := os.WriteFile(jsonFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := importer.ParseFile(jsonFilePath, false)
	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}
}

// TestParseFile_UnsupportedFormat tests error for unsupported file formats
func TestParseFile_UnsupportedFormat(t *testing.T) {
	tempDir := t.TempDir()
	unsupportedFilePath := filepath.Join(tempDir, "test.txt")

	content := `some content`
	if err := os.WriteFile(unsupportedFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := importer.ParseFile(unsupportedFilePath, false)
	if err == nil {
		t.Fatal("Expected error for unsupported format, got nil")
	}
}

// TestReadAndValidateSecretsYML_ValidSecretsFile tests validator integration
func TestReadAndValidateSecretsYML_ValidSecretsFile(t *testing.T) {
	tempDir := t.TempDir()
	secretsFilePath := filepath.Join(tempDir, "secrets.yml")

	content := `metadata:
  profile: testprofile

environments:
  production:
    - name: DB_HOST
      type: envvar
      entry: /database
      key: host
    - name: API_KEY
      type: envvar
      entry: /api
      key: Password`
	if err := os.WriteFile(secretsFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	vm := validator.NewManager()
	root, err := vm.ReadAndValidateSecretsYML(secretsFilePath)
	if err != nil {
		t.Fatalf("ReadAndValidateSecretsYML failed: %v", err)
	}

	if len(root.Profiles) != 1 {
		t.Errorf("Expected 1 profile, got %d", len(root.Profiles))
	}
	if root.Profiles[0].Metadata.Profile != "testprofile" {
		t.Errorf("Expected profile name 'testprofile', got '%s'", root.Profiles[0].Metadata.Profile)
	}
	if len(root.Profiles[0].Environments) != 1 {
		t.Errorf("Expected 1 environment, got %d", len(root.Profiles[0].Environments))
	}
	if items, ok := root.Profiles[0].Environments["production"]; !ok {
		t.Error("Expected 'production' environment to exist")
	} else if len(items) != 2 {
		t.Errorf("Expected 2 items in production, got %d", len(items))
	}
}

// NOTE: Tests for import_variables and import_contents commands are intentionally
// simple and test only the parser/validation logic. Full integration tests would
// require complex mocking of KeePassManager which is already covered by existing
// integration tests. These tests focus on:
// - Parser format detection and parsing correctness
// - Base64 encoding/decoding
// - Validator integration with secrets.yml
// - File I/O operations (reading content, filename matching)

// TestReadAndValidateSecretsYML_InvalidFile tests error handling for invalid secrets.yml
func TestReadAndValidateSecretsYML_InvalidFile(t *testing.T) {
	tempDir := t.TempDir()
	secretsFilePath := filepath.Join(tempDir, "secrets.yml")

	// Missing required field 'profile' in metadata
	content := `metadata:
  other_field: something

environments:
  production: []`
	if err := os.WriteFile(secretsFilePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	vm := validator.NewManager()
	_, err := vm.ReadAndValidateSecretsYML(secretsFilePath)
	if err == nil {
		t.Fatal("Expected error for invalid secrets.yml, got nil")
	}
}

// TestReadAndValidateSecretsYML_FileNotFound tests error when secrets.yml doesn't exist
func TestReadAndValidateSecretsYML_FileNotFound(t *testing.T) {
	vm := validator.NewManager()
	_, err := vm.ReadAndValidateSecretsYML("/nonexistent/secrets.yml")
	if err == nil {
		t.Fatal("Expected error for non-existent file, got nil")
	}
}
