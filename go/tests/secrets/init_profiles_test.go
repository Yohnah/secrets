package secrets_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/keepass"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/output"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/Yohnah/secrets/internal/secrets/initialize"
	"github.com/Yohnah/secrets/internal/types"
	"github.com/Yohnah/secrets/internal/validator"
)

// TestCreateProfile tests the KeePassManager.CreateProfile method
func TestCreateProfile(t *testing.T) {
	// Setup: Create temporary directory
	tempDir := t.TempDir()

	// Create temporary database and keyfile paths
	dbPath := filepath.Join(tempDir, "test.kdbx")
	keyfilePath := filepath.Join(tempDir, "test.key")
	password := "testpassword123"

	// Create KeePassManager
	keepassManager := keepass.NewManager()

	// Generate keyfile first
	err := keepassManager.GenerateKeyfile(keyfilePath)
	if err != nil {
		t.Fatalf("Failed to generate keyfile: %v", err)
	}

	// Create database
	err = keepassManager.CreateDatabase(dbPath, keyfilePath, password, "TEST_ROOT")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	// Test: Create profile
	profileName := "test-profile"
	err = keepassManager.CreateProfile(dbPath, keyfilePath, password, profileName)
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	// Verify: Profile was created
	db, err := keepassManager.OpenDatabase(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	// Check root group exists
	if len(db.Content.Root.Groups) == 0 {
		t.Fatal("Database has no root group")
	}

	rootGroup := &db.Content.Root.Groups[0]

	// Find profile
	profileFound := false
	for _, group := range rootGroup.Groups {
		if group.Name == profileName {
			profileFound = true

			// Verify HEAD group exists
			if len(group.Groups) == 0 {
				t.Error("Profile has no HEAD group")
				continue
			}

			headGroup := group.Groups[0]
			if headGroup.Name != "HEAD" {
				t.Errorf("Expected HEAD group, got: %s", headGroup.Name)
			}

			// Verify metadata entry exists
			if len(headGroup.Entries) == 0 {
				t.Error("HEAD group has no metadata entry")
				continue
			}

			metadataEntry := headGroup.Entries[0]

			// Verify fields
			titleFound := false
			versionFound := false
			datetimeFound := false

			for _, value := range metadataEntry.Values {
				switch value.Key {
				case "Title":
					if value.Value.Content != "metadata" {
						t.Errorf("Expected Title 'metadata', got: %s", value.Value.Content)
					}
					titleFound = true
				case "version":
					if value.Value.Content != "1" {
						t.Errorf("Expected version '1', got: %s", value.Value.Content)
					}
					versionFound = true
				case "datetime":
					if value.Value.Content == "" {
						t.Error("datetime field is empty")
					}
					datetimeFound = true
				}
			}

			if !titleFound {
				t.Error("Title field not found in metadata entry")
			}
			if !versionFound {
				t.Error("version field not found in metadata entry")
			}
			if !datetimeFound {
				t.Error("datetime field not found in metadata entry")
			}

			break
		}
	}

	if !profileFound {
		t.Errorf("Profile '%s' was not created", profileName)
	}
}

// TestCreateProfileIdempotent tests that creating the same profile twice is idempotent
func TestCreateProfileIdempotent(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.kdbx")
	keyfilePath := filepath.Join(tempDir, "test.key")
	password := "testpassword123"

	keepassManager := keepass.NewManager()

	// Generate keyfile first
	err := keepassManager.GenerateKeyfile(keyfilePath)
	if err != nil {
		t.Fatalf("Failed to generate keyfile: %v", err)
	}

	// Create database
	err = keepassManager.CreateDatabase(dbPath, keyfilePath, password, "TEST_ROOT")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	// Create profile first time
	profileName := "idempotent-profile"
	err = keepassManager.CreateProfile(dbPath, keyfilePath, password, profileName)
	if err != nil {
		t.Fatalf("First CreateProfile failed: %v", err)
	}

	// Create profile second time (should be idempotent - no error)
	err = keepassManager.CreateProfile(dbPath, keyfilePath, password, profileName)
	if err != nil {
		t.Fatalf("Second CreateProfile failed: %v", err)
	}

	// Verify: Only ONE profile exists
	db, err := keepassManager.OpenDatabase(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	rootGroup := &db.Content.Root.Groups[0]

	profileCount := 0
	for _, group := range rootGroup.Groups {
		if group.Name == profileName {
			profileCount++
		}
	}

	if profileCount != 1 {
		t.Errorf("Expected 1 profile, found %d", profileCount)
	}
}

// TestProfileExists tests the ProfileExists method
func TestProfileExists(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.kdbx")
	keyfilePath := filepath.Join(tempDir, "test.key")
	password := "testpassword123"

	keepassManager := keepass.NewManager()

	// Generate keyfile first
	err := keepassManager.GenerateKeyfile(keyfilePath)
	if err != nil {
		t.Fatalf("Failed to generate keyfile: %v", err)
	}

	// Create database
	err = keepassManager.CreateDatabase(dbPath, keyfilePath, password, "TEST_ROOT")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	// Test: Profile should NOT exist initially
	exists, err := keepassManager.ProfileExists(dbPath, keyfilePath, password, "non-existent")
	if err != nil {
		t.Fatalf("ProfileExists failed: %v", err)
	}
	if exists {
		t.Error("ProfileExists returned true for non-existent profile")
	}

	// Create profile
	profileName := "existing-profile"
	err = keepassManager.CreateProfile(dbPath, keyfilePath, password, profileName)
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	// Test: Profile SHOULD exist now
	exists, err = keepassManager.ProfileExists(dbPath, keyfilePath, password, profileName)
	if err != nil {
		t.Fatalf("ProfileExists failed: %v", err)
	}
	if !exists {
		t.Error("ProfileExists returned false for existing profile")
	}
}

// TestInitWithSecretsYML tests Init command integration with secrets.yml
func TestInitWithSecretsYML(t *testing.T) {
	// Setup
	tempDir := t.TempDir()

	// Create secrets.yml
	secretsYMLContent := `metadata:
  profile: "integration-test"
  default_environment: "production"

environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Production/DB"
      key: "Password"

outputs: {}`

	secretsYMLPath := filepath.Join(tempDir, "secrets.yml")
	if err := os.WriteFile(secretsYMLPath, []byte(secretsYMLContent), 0644); err != nil {
		t.Fatalf("Failed to create secrets.yml: %v", err)
	}

	// Set password env var
	os.Setenv("SECRETS_YOHNAH_PASSWORD", "testpassword123")
	defer os.Unsetenv("SECRETS_YOHNAH_PASSWORD")

	// Create paths
	secretsDir := filepath.Join(tempDir, ".secrets_yohnah")
	dbPath := filepath.Join(secretsDir, "secrets.kdbx")
	keyfilePath := filepath.Join(secretsDir, "secrets.key")

	// Change to temp directory
	oldWd, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(oldWd)

	// Create managers manually
	globalFlags := &types.GlobalFlags{
		Database:         dbPath,
		Keyfile:          keyfilePath,
		SecretsFile:      secretsYMLPath,
		IgnoreGitProject: true,
		IgnoreConfigFile: false,
		Force:            true,
		Verbose:          false,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(globalFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	outputMgr := output.NewManager()
	keepassMgr := keepass.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepassMgr, outputMgr, validatorMgr)

	// Execute: Run init
	err := secretsMgr.Init(initialize.Options{
		ForceRecreate:    false,
		NoCreateDatabase: false,
		DatabaseName:     "TEST_DB",
	})

	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify: Profile was created
	db, err := keepassMgr.OpenDatabase(dbPath, keyfilePath, "testpassword123")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	rootGroup := &db.Content.Root.Groups[0]

	profileFound := false
	for _, group := range rootGroup.Groups {
		if group.Name == "integration-test" {
			profileFound = true
			break
		}
	}

	if !profileFound {
		t.Error("Profile 'integration-test' was not created from secrets.yml")
	}
}

// TestInitWithCustomSecretsFile tests Init command with --secrets-file flag
func TestInitWithCustomSecretsFile(t *testing.T) {
	// Setup
	tempDir := t.TempDir()

	// Create secrets.yml in a custom location
	customDir := filepath.Join(tempDir, "custom")
	if err := os.MkdirAll(customDir, 0755); err != nil {
		t.Fatalf("Failed to create custom directory: %v", err)
	}

	secretsYMLContent := `metadata:
  profile: "custom-location-profile"
  default_environment: "production"

environments:
  production:
    - name: "API_KEY"
      type: "envvar"
      entry: "/Production/API"
      key: "token"

outputs: {}`

	customSecretsPath := filepath.Join(customDir, "my-secrets.yml")
	if err := os.WriteFile(customSecretsPath, []byte(secretsYMLContent), 0644); err != nil {
		t.Fatalf("Failed to create custom secrets file: %v", err)
	}

	// Set password env var
	os.Setenv("SECRETS_YOHNAH_PASSWORD", "testpassword123")
	defer os.Unsetenv("SECRETS_YOHNAH_PASSWORD")

	// Create paths
	secretsDir := filepath.Join(tempDir, ".secrets_yohnah")
	dbPath := filepath.Join(secretsDir, "secrets.kdbx")
	keyfilePath := filepath.Join(secretsDir, "secrets.key")

	// Change to temp directory
	oldWd, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(oldWd)

	// Create managers manually with --secrets-file flag pointing to custom location
	globalFlags := &types.GlobalFlags{
		Database:         dbPath,
		Keyfile:          keyfilePath,
		SecretsFile:      customSecretsPath, // <-- Custom location
		IgnoreGitProject: true,
		IgnoreConfigFile: false,
		Force:            true,
		Verbose:          false,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(globalFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	outputMgr := output.NewManager()
	keepassMgr := keepass.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepassMgr, outputMgr, validatorMgr)

	// Execute: Run init
	err := secretsMgr.Init(initialize.Options{
		ForceRecreate:    false,
		NoCreateDatabase: false,
		DatabaseName:     "TEST_DB",
	})

	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify: Profile was created from custom location
	db, err := keepassMgr.OpenDatabase(dbPath, keyfilePath, "testpassword123")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	rootGroup := &db.Content.Root.Groups[0]

	profileFound := false
	for _, group := range rootGroup.Groups {
		if group.Name == "custom-location-profile" {
			profileFound = true
			break
		}
	}

	if !profileFound {
		t.Error("Profile 'custom-location-profile' was not created from custom secrets file")
	}

	// Verify secrets.yml in current directory was NOT used (if it existed)
	// This test explicitly uses --secrets-file flag
	t.Logf("✓ Profile loaded from custom location: %s", customSecretsPath)
}

// TestInitUsesCurrentDirSecretsYML tests that without --secrets-file, it uses secrets.yml in current directory
func TestInitUsesCurrentDirSecretsYML(t *testing.T) {
	// Setup
	tempDir := t.TempDir()

	// Create secrets.yml in current directory
	secretsYMLContent := `metadata:
  profile: "current-dir-profile"
  default_environment: "dev"

environments:
  dev:
    - name: "LOCAL_SECRET"
      type: "text"
      entry: "/Dev/Local"
      key: "secret"

outputs: {}`

	secretsYMLPath := filepath.Join(tempDir, "secrets.yml")
	if err := os.WriteFile(secretsYMLPath, []byte(secretsYMLContent), 0644); err != nil {
		t.Fatalf("Failed to create secrets.yml: %v", err)
	}

	// Create another secrets file in a different location (should NOT be used)
	otherDir := filepath.Join(tempDir, "other")
	if err := os.MkdirAll(otherDir, 0755); err != nil {
		t.Fatalf("Failed to create other directory: %v", err)
	}

	otherSecretsContent := `metadata:
  profile: "should-not-be-loaded"
  default_environment: "prod"

environments:
  prod:
    - name: "OTHER_SECRET"
      type: "text"
      entry: "/Prod/Other"
      key: "secret"

outputs: {}`

	otherSecretsPath := filepath.Join(otherDir, "other-secrets.yml")
	if err := os.WriteFile(otherSecretsPath, []byte(otherSecretsContent), 0644); err != nil {
		t.Fatalf("Failed to create other secrets file: %v", err)
	}

	// Set password env var
	os.Setenv("SECRETS_YOHNAH_PASSWORD", "testpassword123")
	defer os.Unsetenv("SECRETS_YOHNAH_PASSWORD")

	// Create paths
	secretsDir := filepath.Join(tempDir, ".secrets_yohnah")
	dbPath := filepath.Join(secretsDir, "secrets.kdbx")
	keyfilePath := filepath.Join(secretsDir, "secrets.key")

	// Change to temp directory (so secrets.yml is in current dir)
	oldWd, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(oldWd)

	// Create managers WITHOUT --secrets-file flag (should use current dir secrets.yml)
	globalFlags := &types.GlobalFlags{
		Database:         dbPath,
		Keyfile:          keyfilePath,
		SecretsFile:      "", // <-- No custom location, should use current dir
		IgnoreGitProject: true,
		IgnoreConfigFile: false,
		Force:            true,
		Verbose:          false,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(globalFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	outputMgr := output.NewManager()
	keepassMgr := keepass.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, keepassMgr, outputMgr, validatorMgr)

	// Execute: Run init
	err := secretsMgr.Init(initialize.Options{
		ForceRecreate:    false,
		NoCreateDatabase: false,
		DatabaseName:     "TEST_DB",
	})

	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify: Profile from current directory was loaded
	db, err := keepassMgr.OpenDatabase(dbPath, keyfilePath, "testpassword123")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	rootGroup := &db.Content.Root.Groups[0]

	// Check correct profile was loaded
	currentDirProfileFound := false
	otherProfileFound := false

	for _, group := range rootGroup.Groups {
		if group.Name == "current-dir-profile" {
			currentDirProfileFound = true
		}
		if group.Name == "should-not-be-loaded" {
			otherProfileFound = true
		}
	}

	if !currentDirProfileFound {
		t.Error("Profile 'current-dir-profile' from current directory secrets.yml was not loaded")
	}

	if otherProfileFound {
		t.Error("Profile 'should-not-be-loaded' from other location was incorrectly loaded")
	}

	t.Logf("✓ Profile loaded from current directory: %s", secretsYMLPath)
}
