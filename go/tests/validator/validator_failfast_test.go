package validator_test

import (
	"testing"

	"github.com/Yohnah/secrets/internal/validator"
)

// TestValidateUniqueProfileInRoot tests the fail-fast profile validation
func TestValidateUniqueProfileInRoot(t *testing.T) {
	mgr := validator.NewManager()

	tests := []struct {
		name        string
		profiles    []string
		profileName string
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "unique profile - no duplicates",
			profiles:    []string{"dev", "prod", "staging"},
			profileName: "dev",
			shouldError: false,
		},
		{
			name:        "duplicate profile - exact case",
			profiles:    []string{"dev", "dev", "prod"},
			profileName: "dev",
			shouldError: true,
			errorMsg:    "database corruption: found 2 profiles named 'dev' in ROOT",
		},
		{
			name:        "duplicate profile - case insensitive",
			profiles:    []string{"Dev", "dev", "prod"},
			profileName: "dev",
			shouldError: true,
			errorMsg:    "database corruption: found 2 profiles named 'dev' in ROOT",
		},
		{
			name:        "duplicate with spaces - normalization",
			profiles:    []string{"dev ", " dev", "prod"},
			profileName: "dev",
			shouldError: true,
			errorMsg:    "database corruption: found 2 profiles named 'dev' in ROOT",
		},
		{
			name:        "three duplicates",
			profiles:    []string{"dev", "dev", "dev", "prod"},
			profileName: "dev",
			shouldError: true,
			errorMsg:    "database corruption: found 3 profiles named 'dev' in ROOT",
		},
		{
			name:        "profile not in list",
			profiles:    []string{"prod", "staging"},
			profileName: "dev",
			shouldError: false,
		},
		{
			name:        "empty profiles list",
			profiles:    []string{},
			profileName: "dev",
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.ValidateUniqueProfileInRoot(tt.profiles, tt.profileName)

			if tt.shouldError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && err.Error()[:len(tt.errorMsg)] != tt.errorMsg {
					t.Errorf("expected error message to start with %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
			}
		})
	}
}

// TestValidateUniqueEntryInPath tests the fail-fast entry path validation
func TestValidateUniqueEntryInPath(t *testing.T) {
	mgr := validator.NewManager()

	tests := []struct {
		name        string
		entries     []string
		entryName   string
		fullPath    string
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "unique entry - no duplicates",
			entries:     []string{"app1", "app2", "app3"},
			entryName:   "app1",
			fullPath:    "dev/databases/app1",
			shouldError: false,
		},
		{
			name:        "duplicate entry - exact case",
			entries:     []string{"app1", "app1", "app2"},
			entryName:   "app1",
			fullPath:    "dev/databases/app1",
			shouldError: true,
			errorMsg:    "database corruption: found 2 entries named 'app1' at path 'dev/databases/app1'",
		},
		{
			name:        "duplicate entry - case insensitive",
			entries:     []string{"App1", "app1", "app2"},
			entryName:   "app1",
			fullPath:    "dev/databases/app1",
			shouldError: true,
			errorMsg:    "database corruption: found 2 entries named 'app1' at path 'dev/databases/app1'",
		},
		{
			name:        "duplicate with spaces - normalization",
			entries:     []string{"app1 ", " app1", "app2"},
			entryName:   "app1",
			fullPath:    "dev/databases/app1",
			shouldError: true,
			errorMsg:    "database corruption: found 2 entries named 'app1' at path 'dev/databases/app1'",
		},
		{
			name:        "multiple duplicates",
			entries:     []string{"app1", "app1", "app1", "app2"},
			entryName:   "app1",
			fullPath:    "dev/databases/app1",
			shouldError: true,
			errorMsg:    "database corruption: found 3 entries named 'app1' at path 'dev/databases/app1'",
		},
		{
			name:        "entry not in list",
			entries:     []string{"app2", "app3"},
			entryName:   "app1",
			fullPath:    "dev/databases/app1",
			shouldError: false,
		},
		{
			name:        "empty entries list",
			entries:     []string{},
			entryName:   "app1",
			fullPath:    "dev/databases/app1",
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.ValidateUniqueEntryInPath(tt.entries, tt.entryName, tt.fullPath)

			if tt.shouldError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && err.Error()[:len(tt.errorMsg)] != tt.errorMsg {
					t.Errorf("expected error message to start with %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
			}
		})
	}
}

// TestValidateUniqueFieldsInEntry tests the fail-fast field validation
func TestValidateUniqueFieldsInEntry(t *testing.T) {
	mgr := validator.NewManager()

	tests := []struct {
		name        string
		fields      []string
		entryPath   string
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "no duplicates - standard fields",
			fields:      []string{"Title", "UserName", "Password", "URL", "Notes"},
			entryPath:   "dev/databases/app1",
			shouldError: false,
		},
		{
			name:        "no duplicates - mixed standard and custom",
			fields:      []string{"Title", "UserName", "Password", "CustomField1", "CustomField2"},
			entryPath:   "dev/databases/app1",
			shouldError: false,
		},
		{
			name:        "duplicate standard field - case insensitive",
			fields:      []string{"Title", "title", "UserName"},
			entryPath:   "dev/databases/app1",
			shouldError: true,
			errorMsg:    "database corruption: found duplicate standard field 'title' (case-insensitive, also found as 'Title')",
		},
		{
			name:        "duplicate standard field - different cases",
			fields:      []string{"Password", "PASSWORD", "UserName"},
			entryPath:   "dev/databases/app1",
			shouldError: true,
			errorMsg:    "database corruption: found duplicate standard field 'PASSWORD' (case-insensitive, also found as 'Password')",
		},
		{
			name:        "duplicate custom field - exact case",
			fields:      []string{"Title", "CustomField", "CustomField"},
			entryPath:   "dev/databases/app1",
			shouldError: true,
			errorMsg:    "database corruption: found duplicate custom field 'CustomField' (case-sensitive)",
		},
		{
			name:        "custom fields - different case allowed",
			fields:      []string{"Title", "CustomField", "customfield"},
			entryPath:   "dev/databases/app1",
			shouldError: false,
		},
		{
			name:        "duplicate with spaces - standard field",
			fields:      []string{"Title ", " Title", "UserName"},
			entryPath:   "dev/databases/app1",
			shouldError: true,
			errorMsg:    "database corruption: found duplicate standard field ' Title' (case-insensitive, also found as 'Title ')",
		},
		{
			name:        "duplicate with spaces - custom field",
			fields:      []string{"Title", "Custom ", " Custom"},
			entryPath:   "dev/databases/app1",
			shouldError: true,
			errorMsg:    "database corruption: found duplicate custom field ' Custom' (case-sensitive)",
		},
		{
			name:        "empty fields list",
			fields:      []string{},
			entryPath:   "dev/databases/app1",
			shouldError: false,
		},
		{
			name:        "all standard fields - various cases",
			fields:      []string{"title", "USERNAME", "password", "url", "NOTES"},
			entryPath:   "dev/databases/app1",
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.ValidateUniqueFieldsInEntry(tt.fields, tt.entryPath)

			if tt.shouldError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && err.Error()[:len(tt.errorMsg)] != tt.errorMsg {
					t.Errorf("expected error message to start with %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
			}
		})
	}
}

// TestValidateUniqueFieldsInEntry_EdgeCases tests edge cases for field validation
func TestValidateUniqueFieldsInEntry_EdgeCases(t *testing.T) {
	mgr := validator.NewManager()

	tests := []struct {
		name        string
		fields      []string
		entryPath   string
		shouldError bool
		description string
	}{
		{
			name:        "mix of standard and custom with potential conflicts",
			fields:      []string{"Title", "title_backup", "UserName", "username_old", "Password"},
			entryPath:   "dev/app",
			shouldError: false,
			description: "Custom fields similar to standard ones should be allowed",
		},
		{
			name:        "many custom fields no duplicates",
			fields:      []string{"Title", "API_KEY", "DB_HOST", "DB_PORT", "DB_NAME", "EXTRA_CONFIG"},
			entryPath:   "dev/app",
			shouldError: false,
			description: "Multiple unique custom fields should work",
		},
		{
			name:        "standard field with mixed case first occurrence",
			fields:      []string{"TiTlE", "title"},
			entryPath:   "dev/app",
			shouldError: true,
			description: "Standard fields are case-insensitive regardless of first occurrence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.ValidateUniqueFieldsInEntry(tt.fields, tt.entryPath)

			if tt.shouldError && err == nil {
				t.Errorf("%s: expected error but got none", tt.description)
			} else if !tt.shouldError && err != nil {
				t.Errorf("%s: expected no error but got: %v", tt.description, err)
			}
		})
	}
}
