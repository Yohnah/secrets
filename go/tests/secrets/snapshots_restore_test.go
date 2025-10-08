package secrets

import (
"os"
"path/filepath"
"testing"

"github.com/Yohnah/secrets/internal/testhelpers"
)

func TestSnapshotsRestore_Success(t *testing.T) {
// Setup test environment
testDir := t.TempDir()
secretsFile := filepath.Join(testDir, "secrets.yml")
dbFile := filepath.Join(testDir, "test.kdbx")
keyfile := filepath.Join(testDir, "test.key")

// Create minimal secrets.yml
secretsContent := `metadata:
  profile: "test-profile"
  default_environment: "production"
environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/DB"
      key: "Password"
outputs: {}`

err := os.WriteFile(secretsFile, []byte(secretsContent), 0644)
if err != nil {
t.Fatalf("Failed to create secrets.yml: %v", err)
}

// Initialize database and create profile with snapshots
cmd := testhelpers.RunCommand("init", "--secrets-file", secretsFile, "--db", dbFile, "--keyfile", keyfile)
cmd.Env = append(cmd.Env, "SECRETS_YOHNAH_PASSWORD=123456")
if err := cmd.Run(); err != nil {
t.Fatalf("Failed to init database: %v", err)
}

// Create first snapshot (v1)
cmd = testhelpers.RunCommand("snapshots", "new", "test-profile", "--secrets-file", secretsFile, "--db", dbFile, "--keyfile", keyfile, "-f")
cmd.Env = append(cmd.Env, "SECRETS_YOHNAH_PASSWORD=123456")
if err := cmd.Run(); err != nil {
t.Fatalf("Failed to create first snapshot: %v", err)
}

// Create second snapshot (v2)
cmd = testhelpers.RunCommand("snapshots", "new", "test-profile", "--secrets-file", secretsFile, "--db", dbFile, "--keyfile", keyfile, "-f")
cmd.Env = append(cmd.Env, "SECRETS_YOHNAH_PASSWORD=123456")
if err := cmd.Run(); err != nil {
t.Fatalf("Failed to create second snapshot: %v", err)
}

// Now HEAD should be v3, and we have v1 and v2 snapshots

// Restore v1
cmd = testhelpers.RunCommand("snapshots", "restore", "test-profile", "v1", "--secrets-file", secretsFile, "--db", dbFile, "--keyfile", keyfile, "-f")
cmd.Env = append(cmd.Env, "SECRETS_YOHNAH_PASSWORD=123456")
output, err := cmd.CombinedOutput()
if err != nil {
t.Fatalf("Failed to restore snapshot v1: %v\nOutput: %s", err, output)
}

// Verify success messages
outputStr := string(output)
if !testhelpers.ContainsString(outputStr, "Snapshot 'v1' restored successfully to HEAD") {
t.Errorf("Expected success message not found in output: %s", outputStr)
}
if !testhelpers.ContainsString(outputStr, "Old HEAD (v3) preserved as v3") {
t.Errorf("Expected preservation message not found in output: %s", outputStr)
}
if !testhelpers.ContainsString(outputStr, "New HEAD version: v4") {
t.Errorf("Expected new HEAD version message not found in output: %s", outputStr)
}
}

func TestSnapshotsRestore_ProfileNotInSecretsYML(t *testing.T) {
// Setup test environment
testDir := t.TempDir()
secretsFile := filepath.Join(testDir, "secrets.yml")
dbFile := filepath.Join(testDir, "test.kdbx")
keyfile := filepath.Join(testDir, "test.key")

// Create minimal secrets.yml with different profile
secretsContent := `metadata:
  profile: "test-profile"
  default_environment: "production"
environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/DB"
      key: "Password"
outputs: {}`

err := os.WriteFile(secretsFile, []byte(secretsContent), 0644)
if err != nil {
t.Fatalf("Failed to create secrets.yml: %v", err)
}

// Initialize database
cmd := testhelpers.RunCommand("init", "--secrets-file", secretsFile, "--db", dbFile, "--keyfile", keyfile)
cmd.Env = append(cmd.Env, "SECRETS_YOHNAH_PASSWORD=123456")
if err := cmd.Run(); err != nil {
t.Fatalf("Failed to init database: %v", err)
}

// Try to restore for non-existent profile
cmd = testhelpers.RunCommand("snapshots", "restore", "non-existent-profile", "v1", "--secrets-file", secretsFile, "--db", dbFile, "--keyfile", keyfile, "-f")
cmd.Env = append(cmd.Env, "SECRETS_YOHNAH_PASSWORD=123456")
output, err := cmd.CombinedOutput()

// Should fail
if err == nil {
t.Fatal("Expected error for non-existent profile, but command succeeded")
}

// Verify error message
outputStr := string(output)
if !testhelpers.ContainsString(outputStr, "does not exist in secrets.yml") {
t.Errorf("Expected error message about profile not in secrets.yml, got: %s", outputStr)
}
}

func TestSnapshotsRestore_SnapshotNotExists(t *testing.T) {
// Setup test environment
testDir := t.TempDir()
secretsFile := filepath.Join(testDir, "secrets.yml")
dbFile := filepath.Join(testDir, "test.kdbx")
keyfile := filepath.Join(testDir, "test.key")

// Create minimal secrets.yml
secretsContent := `metadata:
  profile: "test-profile"
  default_environment: "production"
environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/DB"
      key: "Password"
outputs: {}`

err := os.WriteFile(secretsFile, []byte(secretsContent), 0644)
if err != nil {
t.Fatalf("Failed to create secrets.yml: %v", err)
}

// Initialize database
cmd := testhelpers.RunCommand("init", "--secrets-file", secretsFile, "--db", dbFile, "--keyfile", keyfile)
cmd.Env = append(cmd.Env, "SECRETS_YOHNAH_PASSWORD=123456")
if err := cmd.Run(); err != nil {
t.Fatalf("Failed to init database: %v", err)
}

// Try to restore non-existent snapshot
cmd = testhelpers.RunCommand("snapshots", "restore", "test-profile", "v999", "--secrets-file", secretsFile, "--db", dbFile, "--keyfile", keyfile, "-f")
cmd.Env = append(cmd.Env, "SECRETS_YOHNAH_PASSWORD=123456")
output, err := cmd.CombinedOutput()

// Should fail
if err == nil {
t.Fatal("Expected error for non-existent snapshot, but command succeeded")
}

// Verify error message
outputStr := string(output)
if !testhelpers.ContainsString(outputStr, "does not exist for profile") {
t.Errorf("Expected error message about snapshot not existing, got: %s", outputStr)
}
}

func TestSnapshotsRestore_NoInteractiveWithoutPassword(t *testing.T) {
// Setup test environment
testDir := t.TempDir()
secretsFile := filepath.Join(testDir, "secrets.yml")
dbFile := filepath.Join(testDir, "test.kdbx")
keyfile := filepath.Join(testDir, "test.key")

// Create minimal secrets.yml
secretsContent := `metadata:
  profile: "test-profile"
  default_environment: "production"
environments:
  production:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/DB"
      key: "Password"
outputs: {}`

err := os.WriteFile(secretsFile, []byte(secretsContent), 0644)
if err != nil {
t.Fatalf("Failed to create secrets.yml: %v", err)
}

// Initialize database
cmd := testhelpers.RunCommand("init", "--secrets-file", secretsFile, "--db", dbFile, "--keyfile", keyfile)
cmd.Env = append(cmd.Env, "SECRETS_YOHNAH_PASSWORD=123456")
if err := cmd.Run(); err != nil {
t.Fatalf("Failed to init database: %v", err)
}

// Create snapshot
cmd = testhelpers.RunCommand("snapshots", "new", "test-profile", "--secrets-file", secretsFile, "--db", dbFile, "--keyfile", keyfile, "-f")
cmd.Env = append(cmd.Env, "SECRETS_YOHNAH_PASSWORD=123456")
if err := cmd.Run(); err != nil {
t.Fatalf("Failed to create snapshot: %v", err)
}

// Try to restore with -f flag but without password env var
cmd = testhelpers.RunCommand("snapshots", "restore", "test-profile", "v1", "--secrets-file", secretsFile, "--db", dbFile, "--keyfile", keyfile, "-f")
// Intentionally NOT setting SECRETS_YOHNAH_PASSWORD
output, err := cmd.CombinedOutput()

// Should fail
if err == nil {
t.Fatal("Expected error when using -f without password, but command succeeded")
}

// Verify error message
outputStr := string(output)
if !testhelpers.ContainsString(outputStr, "Password required") || !testhelpers.ContainsString(outputStr, "SECRETS_YOHNAH_PASSWORD") {
t.Errorf("Expected error message about missing password, got: %s", outputStr)
}
}
