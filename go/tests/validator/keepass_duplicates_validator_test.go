package validator_test

import (
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/validator"
)

// mockKeePassManager is a mock implementation of KeePassManager for testing
type mockKeePassManager struct {
	rootGroups     []string
	groupsByParent map[string][]string
	entriesByGroup map[string][]string
	fieldsByEntry  map[string][]string
}

func (m *mockKeePassManager) GetRootGroups() ([]string, error) {
	return m.rootGroups, nil
}

func (m *mockKeePassManager) GetGroupsByParent(parentPath string) ([]string, error) {
	if groups, ok := m.groupsByParent[parentPath]; ok {
		return groups, nil
	}
	return []string{}, nil
}

func (m *mockKeePassManager) GetEntriesByGroup(groupPath string) ([]string, error) {
	if entries, ok := m.entriesByGroup[groupPath]; ok {
		return entries, nil
	}
	return []string{}, nil
}

func (m *mockKeePassManager) GetFieldsByEntry(entryPath string) ([]string, error) {
	if fields, ok := m.fieldsByEntry[entryPath]; ok {
		return fields, nil
	}
	return []string{}, nil
}

// Test: Empty database should return nil (no duplicates)
func TestValidateKeePassDuplicates_EmptyDatabase(t *testing.T) {
	validator := validator.NewManager()
	mockDB := &mockKeePassManager{
		rootGroups:     []string{},
		groupsByParent: map[string][]string{},
		entriesByGroup: map[string][]string{},
		fieldsByEntry:  map[string][]string{},
	}

	errors := validator.ValidateKeePassDuplicates(mockDB)

	if errors != nil {
		t.Errorf("Expected nil for empty database, got %d errors", len(errors))
	}
}

// Test: Database with no duplicates should return nil
func TestValidateKeePassDuplicates_NoDuplicates(t *testing.T) {
	validator := validator.NewManager()
	mockDB := &mockKeePassManager{
		rootGroups: []string{"profile1", "profile2"},
		groupsByParent: map[string][]string{
			"profile1":      {"HEAD", "v1"},
			"profile1/HEAD": {"production", "staging"},
			"profile2":      {"HEAD"},
			"profile2/HEAD": {"development"},
		},
		entriesByGroup: map[string][]string{
			"profile1/HEAD/production":  {"/db", "/api/token"},
			"profile1/HEAD/staging":     {"/db"},
			"profile2/HEAD/development": {"/test_db"},
		},
		fieldsByEntry: map[string][]string{
			"profile1/HEAD/production//db":        {"Password", "UserName"},
			"profile1/HEAD/production//api/token": {"token"},
			"profile1/HEAD/staging//db":           {"Password"},
			"profile2/HEAD/development//test_db":  {"Password"},
		},
	}

	errors := validator.ValidateKeePassDuplicates(mockDB)

	if errors != nil {
		t.Errorf("Expected nil for database without duplicates, got %d errors: %v", len(errors), errors)
	}
}

// Test: Duplicate profiles at ROOT level
func TestValidateKeePassDuplicates_DuplicateProfiles(t *testing.T) {
	validator := validator.NewManager()
	mockDB := &mockKeePassManager{
		rootGroups: []string{"myapp-prod", "myapp-dev", "myapp-prod"}, // Duplicate!
		groupsByParent: map[string][]string{
			"myapp-prod": {"HEAD"},
			"myapp-dev":  {"HEAD"},
		},
		entriesByGroup: map[string][]string{},
		fieldsByEntry:  map[string][]string{},
	}

	errors := validator.ValidateKeePassDuplicates(mockDB)

	if errors == nil {
		t.Fatal("Expected errors for duplicate profiles, got nil")
	}

	if len(errors) == 0 {
		t.Fatal("Expected at least 1 error for duplicate profiles")
	}

	// Check error message contains expected information
	errorMsg := errors[0].Error()
	if !strings.Contains(errorMsg, "duplicate profile 'myapp-prod'") {
		t.Errorf("Error message should mention duplicate profile 'myapp-prod', got: %s", errorMsg)
	}
	if !strings.Contains(errorMsg, "ROOT level") {
		t.Errorf("Error message should mention ROOT level, got: %s", errorMsg)
	}
	if !strings.Contains(errorMsg, "2 occurrences") {
		t.Errorf("Error message should mention 2 occurrences, got: %s", errorMsg)
	}
}

// Test: Duplicate HEAD groups within a profile
func TestValidateKeePassDuplicates_DuplicateHEADs(t *testing.T) {
	validator := validator.NewManager()
	mockDB := &mockKeePassManager{
		rootGroups: []string{"profile1"},
		groupsByParent: map[string][]string{
			"profile1": {"HEAD", "v1", "HEAD"}, // Duplicate HEAD!
		},
		entriesByGroup: map[string][]string{},
		fieldsByEntry:  map[string][]string{},
	}

	errors := validator.ValidateKeePassDuplicates(mockDB)

	if errors == nil {
		t.Fatal("Expected errors for duplicate HEAD groups, got nil")
	}

	errorMsg := errors[0].Error()
	if !strings.Contains(errorMsg, "duplicate tree group 'HEAD'") {
		t.Errorf("Error message should mention duplicate HEAD, got: %s", errorMsg)
	}
	if !strings.Contains(errorMsg, "profile 'profile1'") {
		t.Errorf("Error message should mention profile1, got: %s", errorMsg)
	}
}

// Test: Duplicate environments within a HEAD
func TestValidateKeePassDuplicates_DuplicateEnvironments(t *testing.T) {
	validator := validator.NewManager()
	mockDB := &mockKeePassManager{
		rootGroups: []string{"profile1"},
		groupsByParent: map[string][]string{
			"profile1":      {"HEAD"},
			"profile1/HEAD": {"production", "staging", "production"}, // Duplicate!
		},
		entriesByGroup: map[string][]string{},
		fieldsByEntry:  map[string][]string{},
	}

	errors := validator.ValidateKeePassDuplicates(mockDB)

	if errors == nil {
		t.Fatal("Expected errors for duplicate environments, got nil")
	}

	errorMsg := errors[0].Error()
	if !strings.Contains(errorMsg, "duplicate environment 'production'") {
		t.Errorf("Error message should mention duplicate environment, got: %s", errorMsg)
	}
	if !strings.Contains(errorMsg, "/profile1/HEAD") {
		t.Errorf("Error message should mention location, got: %s", errorMsg)
	}
}

// Test: Duplicate entry paths within an environment
func TestValidateKeePassDuplicates_DuplicateEntryPaths(t *testing.T) {
	validator := validator.NewManager()
	mockDB := &mockKeePassManager{
		rootGroups: []string{"profile1"},
		groupsByParent: map[string][]string{
			"profile1":                 {"HEAD"},
			"profile1/HEAD":            {"production"},
			"profile1/HEAD/production": {},
		},
		entriesByGroup: map[string][]string{
			"profile1/HEAD/production": {"/db", "/api/token", "/db"}, // Duplicate!
		},
		fieldsByEntry: map[string][]string{},
	}

	errors := validator.ValidateKeePassDuplicates(mockDB)

	if errors == nil {
		t.Fatal("Expected errors for duplicate entry paths, got nil")
	}

	errorMsg := errors[0].Error()
	if !strings.Contains(errorMsg, "duplicate entry path '/db'") {
		t.Errorf("Error message should mention duplicate entry path, got: %s", errorMsg)
	}
	if !strings.Contains(errorMsg, "environment 'production'") {
		t.Errorf("Error message should mention environment, got: %s", errorMsg)
	}
}

// Test: Duplicate keys/fields within an entry
func TestValidateKeePassDuplicates_DuplicateKeys(t *testing.T) {
	validator := validator.NewManager()
	mockDB := &mockKeePassManager{
		rootGroups: []string{"profile1"},
		groupsByParent: map[string][]string{
			"profile1":                 {"HEAD"},
			"profile1/HEAD":            {"production"},
			"profile1/HEAD/production": {},
		},
		entriesByGroup: map[string][]string{
			"profile1/HEAD/production": {"/db"},
		},
		fieldsByEntry: map[string][]string{
			"profile1/HEAD/production//db": {"Password", "UserName", "Password"}, // Duplicate!
		},
	}

	errors := validator.ValidateKeePassDuplicates(mockDB)

	if errors == nil {
		t.Fatal("Expected errors for duplicate keys, got nil")
	}

	errorMsg := errors[0].Error()
	if !strings.Contains(errorMsg, "duplicate standard field 'password'") {
		t.Errorf("Error message should mention duplicate field, got: %s", errorMsg)
	}
}

// Test: Case-insensitive standard field duplicates
func TestValidateKeePassDuplicates_CaseInsensitiveStandardFields(t *testing.T) {
	validator := validator.NewManager()
	mockDB := &mockKeePassManager{
		rootGroups: []string{"profile1"},
		groupsByParent: map[string][]string{
			"profile1":                 {"HEAD"},
			"profile1/HEAD":            {"production"},
			"profile1/HEAD/production": {},
		},
		entriesByGroup: map[string][]string{
			"profile1/HEAD/production": {"/db"},
		},
		fieldsByEntry: map[string][]string{
			// PASSWORD and password should be treated as duplicates (case-insensitive)
			"profile1/HEAD/production//db": {"PASSWORD", "username", "password"},
		},
	}

	errors := validator.ValidateKeePassDuplicates(mockDB)

	if errors == nil {
		t.Fatal("Expected errors for case-insensitive duplicate standard fields, got nil")
	}

	errorMsg := errors[0].Error()
	if !strings.Contains(errorMsg, "duplicate standard field 'password'") {
		t.Errorf("Error message should mention duplicate password field, got: %s", errorMsg)
	}
}

// Test: Custom field duplicates (case-sensitive)
func TestValidateKeePassDuplicates_CustomFieldDuplicates(t *testing.T) {
	validator := validator.NewManager()
	mockDB := &mockKeePassManager{
		rootGroups: []string{"profile1"},
		groupsByParent: map[string][]string{
			"profile1":                 {"HEAD"},
			"profile1/HEAD":            {"production"},
			"profile1/HEAD/production": {},
		},
		entriesByGroup: map[string][]string{
			"profile1/HEAD/production": {"/api"},
		},
		fieldsByEntry: map[string][]string{
			// Custom fields ARE case-sensitive
			"profile1/HEAD/production//api": {"api_token", "API_TOKEN", "api_token"},
		},
	}

	errors := validator.ValidateKeePassDuplicates(mockDB)

	if errors == nil {
		t.Fatal("Expected errors for duplicate custom fields, got nil")
	}

	// Should have error for "api_token" duplicate (case-sensitive)
	foundApiTokenError := false
	for _, err := range errors {
		if strings.Contains(err.Error(), "duplicate custom field 'api_token'") {
			foundApiTokenError = true
			break
		}
	}

	if !foundApiTokenError {
		t.Errorf("Expected error for duplicate 'api_token', got errors: %v", errors)
	}
}

// Test: Duplicate attachments
func TestValidateKeePassDuplicates_DuplicateAttachments(t *testing.T) {
	validator := validator.NewManager()
	mockDB := &mockKeePassManager{
		rootGroups: []string{"profile1"},
		groupsByParent: map[string][]string{
			"profile1":                 {"HEAD"},
			"profile1/HEAD":            {"production"},
			"profile1/HEAD/production": {},
		},
		entriesByGroup: map[string][]string{
			"profile1/HEAD/production": {"/ssh"},
		},
		fieldsByEntry: map[string][]string{
			"profile1/HEAD/production//ssh": {
				"attachments/id_rsa",
				"attachments/cert.pem",
				"attachments/id_rsa", // Duplicate!
			},
		},
	}

	errors := validator.ValidateKeePassDuplicates(mockDB)

	if errors == nil {
		t.Fatal("Expected errors for duplicate attachments, got nil")
	}

	errorMsg := errors[0].Error()
	if !strings.Contains(errorMsg, "duplicate attachment 'attachments/id_rsa'") {
		t.Errorf("Error message should mention duplicate attachment, got: %s", errorMsg)
	}
}

// Test: Multiple duplicates should accumulate all errors
func TestValidateKeePassDuplicates_MultipleDuplicates(t *testing.T) {
	validator := validator.NewManager()
	mockDB := &mockKeePassManager{
		rootGroups: []string{"profile1", "profile1"}, // Duplicate profile
		groupsByParent: map[string][]string{
			"profile1":      {"HEAD", "HEAD"},             // Duplicate HEAD
			"profile1/HEAD": {"production", "production"}, // Duplicate environment
		},
		entriesByGroup: map[string][]string{
			"profile1/HEAD/production": {"/db", "/db"}, // Duplicate entry
		},
		fieldsByEntry: map[string][]string{
			"profile1/HEAD/production//db": {"Password", "Password"}, // Duplicate field
		},
	}

	errors := validator.ValidateKeePassDuplicates(mockDB)

	if errors == nil {
		t.Fatal("Expected multiple errors, got nil")
	}

	// Should accumulate ALL errors (at least 5: profile, HEAD, environment, entry, field)
	if len(errors) < 5 {
		t.Errorf("Expected at least 5 accumulated errors, got %d: %v", len(errors), errors)
	}

	// Verify different types of duplicates are detected
	hasProfileError := false
	hasHEADError := false
	hasEnvError := false
	hasEntryError := false
	hasFieldError := false

	for _, err := range errors {
		msg := err.Error()
		if strings.Contains(msg, "duplicate profile") {
			hasProfileError = true
		}
		if strings.Contains(msg, "duplicate tree group 'HEAD'") {
			hasHEADError = true
		}
		if strings.Contains(msg, "duplicate environment") {
			hasEnvError = true
		}
		if strings.Contains(msg, "duplicate entry path") {
			hasEntryError = true
		}
		if strings.Contains(msg, "duplicate standard field") || strings.Contains(msg, "duplicate custom field") {
			hasFieldError = true
		}
	}

	if !hasProfileError {
		t.Error("Expected profile duplicate error")
	}
	if !hasHEADError {
		t.Error("Expected HEAD duplicate error")
	}
	if !hasEnvError {
		t.Error("Expected environment duplicate error")
	}
	if !hasEntryError {
		t.Error("Expected entry duplicate error")
	}
	if !hasFieldError {
		t.Error("Expected field duplicate error")
	}
}

// Test: Error messages contain action suggestions
func TestValidateKeePassDuplicates_ErrorMessagesHaveActions(t *testing.T) {
	validator := validator.NewManager()
	mockDB := &mockKeePassManager{
		rootGroups:     []string{"profile1", "profile1"},
		groupsByParent: map[string][]string{},
		entriesByGroup: map[string][]string{},
		fieldsByEntry:  map[string][]string{},
	}

	errors := validator.ValidateKeePassDuplicates(mockDB)

	if errors == nil || len(errors) == 0 {
		t.Fatal("Expected errors")
	}

	errorMsg := errors[0].Error()
	if !strings.Contains(errorMsg, "Action:") {
		t.Error("Error message should contain 'Action:' section")
	}
	if !strings.Contains(errorMsg, "Remove duplicate") {
		t.Error("Error message should suggest removing duplicate")
	}
	if !strings.Contains(errorMsg, "KeePass client") {
		t.Error("Error message should mention using KeePass client")
	}
}
