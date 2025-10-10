package secrets_test

import (
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/secrets/profile"
)

// TestProfileResolverAutoDetectSingleProfile verifies that the resolver selects the only profile automatically.
func TestProfileResolverAutoDetectSingleProfile(t *testing.T) {
	secretsContent := `---
metadata:
  profile: "auto-detect-profile"
environments:
  development:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Development/DB"
      key: "Password"
outputs: []`

	validatorMgr := newMockValidatorManager(secretsContent)
	configMgr := newMockConfigManager("/tmp/test-secrets.yml")
	loggerMgr := logger.NewManager(false)
	resolver := profile.NewResolver(configMgr, loggerMgr, validatorMgr)

	resolved, err := resolver.Resolve("")
	if err != nil {
		t.Fatalf("expected auto-detection to succeed, got error: %v", err)
	}

	if resolved == nil {
		t.Fatalf("resolver returned nil result")
	}

	if resolved.Name != "auto-detect-profile" {
		t.Fatalf("expected profile name 'auto-detect-profile', got '%s'", resolved.Name)
	}

	if resolved.Profile == nil {
		t.Fatalf("resolved profile pointer is nil")
	}
}

// TestProfileResolverMultipleProfilesRequiresFlag ensures auto-detection fails when multiple profiles exist.
func TestProfileResolverMultipleProfilesRequiresFlag(t *testing.T) {
	secretsContent := `---
metadata:
  profile: "profile-one"
environments:
  development:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Development/DB"
      key: "Password"
outputs: []
---
metadata:
  profile: "profile-two"
environments:
  development:
    - name: "API_TOKEN"
      type: "envvar"
      entry: "/Development/API"
      key: "Token"
outputs: []`

	validatorMgr := newMockValidatorManager(secretsContent)
	configMgr := newMockConfigManager("/tmp/test-secrets.yml")
	loggerMgr := logger.NewManager(false)
	resolver := profile.NewResolver(configMgr, loggerMgr, validatorMgr)

	resolved, err := resolver.Resolve("")
	if err == nil {
		t.Fatalf("expected error due to multiple profiles, got success: %+v", resolved)
	}

	if !strings.Contains(err.Error(), "multiple profiles") {
		t.Fatalf("expected error mentioning multiple profiles, got: %v", err)
	}
}

// TestProfileResolverUnknownProfile verifies that specifying an unknown profile fails.
func TestProfileResolverUnknownProfile(t *testing.T) {
	secretsContent := `---
metadata:
  profile: "known-profile"
environments:
  development:
    - name: "DB_PASSWORD"
      type: "envvar"
      entry: "/Development/DB"
      key: "Password"
outputs: []`

	validatorMgr := newMockValidatorManager(secretsContent)
	configMgr := newMockConfigManager("/tmp/test-secrets.yml")
	loggerMgr := logger.NewManager(false)
	resolver := profile.NewResolver(configMgr, loggerMgr, validatorMgr)

	_, err := resolver.Resolve("unknown-profile")
	if err == nil {
		t.Fatalf("expected error for unknown profile, got nil")
	}

	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected error mentioning missing profile, got: %v", err)
	}
}
