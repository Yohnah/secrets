package secrets_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/logger"
	"github.com/Yohnah/secrets/internal/output"
	"github.com/Yohnah/secrets/internal/prompt"
	"github.com/Yohnah/secrets/internal/secrets"
	"github.com/Yohnah/secrets/internal/types"
	"github.com/Yohnah/secrets/internal/validator"
) // mockOutputManager captures output for testing
type mockOutputManager struct {
	output string
	err    error
}

func (m *mockOutputManager) OutputRaw(content string) error {
	m.output = content
	return m.err
}

func (m *mockOutputManager) Output(data interface{}, format string) error {
	// For testing, just store it as string representation
	m.output = fmt.Sprintf("%v", data)
	return m.err
}

func TestShowTemplate_FullTemplate(t *testing.T) {
	globalFlags := &types.GlobalFlags{
		Config:           "/tmp/test.yml",
		Database:         "/tmp/test.kdbx",
		Keyfile:          "/tmp/test.keyfile",
		IgnoreConfigFile: true,
		Verbose:          false,
	}
	commandFlags := &types.CommandFlags{
		TemplateName: config.SecretsYMLFilename,
	}
	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(globalFlags, commandFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	outputMock := &mockOutputManager{}

	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), outputMock, newMockTemplateManager(), validator.NewManager())

	// Test full template
	err := secretsMgr.ShowTemplate()
	if err != nil {
		t.Fatalf("ShowTemplate(false) error: %v", err)
	}

	template := outputMock.output
	if template == "" {
		t.Fatal("ShowTemplate() returned empty template")
	}
	if len(template) < 100 {
		t.Fatalf("ShowTemplate() too short: %d bytes", len(template))
	}

	// Check expected content in full template
	expected := []string{
		"This file defines the structure and mapping of secrets for your project",
		"metadata:",
		"environments:",
		"outputs:",
		"profile:",
		"COMPLETE EXAMPLE",
		"FIELD REFERENCE",
	}
	for _, s := range expected {
		if !strings.Contains(template, s) {
			t.Errorf("Full template missing: %s", s)
		}
	}
}

func TestShowTemplate_MinimalTemplate(t *testing.T) {
	globalFlags := &types.GlobalFlags{
		Config:           "/tmp/test.yml",
		Database:         "/tmp/test.kdbx",
		Keyfile:          "/tmp/test.keyfile",
		IgnoreConfigFile: true,
		Verbose:          false,
	}

	commandFlags := &types.CommandFlags{
		Minimal:      true,
		TemplateName: config.SecretsYMLFilename,
	}

	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(globalFlags, commandFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()
	outputMock := &mockOutputManager{}

	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), outputMock, newMockTemplateManager(), validator.NewManager())

	// Test minimal template
	err := secretsMgr.ShowTemplate()
	if err != nil {
		t.Fatalf("ShowTemplate(true) error: %v", err)
	}

	template := outputMock.output
	if template == "" {
		t.Fatal("ShowTemplate() returned empty minimal template")
	}

	// Check that minimal template has basic structure
	requiredInMinimal := []string{
		"metadata:",
		"environments:",
		"outputs:",
		"profile:",
	}
	for _, s := range requiredInMinimal {
		if !strings.Contains(template, s) {
			t.Errorf("Minimal template missing required field: %s", s)
		}
	}

	// Check that minimal template does NOT have examples and documentation
	shouldNotHaveInMinimal := []string{
		"COMPLETE EXAMPLE",
		"FIELD REFERENCE",
		"This file defines the structure and mapping of secrets for your project",
	}
	for _, s := range shouldNotHaveInMinimal {
		if strings.Contains(template, s) {
			t.Errorf("Minimal template should not contain: %s", s)
		}
	}

	// Minimal should be shorter than full
	outputMock2 := &mockOutputManager{}
	commandFlags2 := &types.CommandFlags{
		Minimal:      false,
		TemplateName: config.SecretsYMLFilename,
	}
	configMgr2 := config.NewManager(globalFlags, commandFlags2, validatorMgr)
	secretsMgr2 := secrets.NewManager(configMgr2, loggerMgr, promptMgr, newMockKeePassManager(), outputMock2, newMockTemplateManager(), validator.NewManager())
	_ = secretsMgr2.ShowTemplate()
	fullTemplate := outputMock2.output

	if len(template) >= len(fullTemplate) {
		t.Errorf("Minimal template (%d bytes) should be shorter than full template (%d bytes)",
			len(template), len(fullTemplate))
	}
}

func TestShowTemplate_UsesOutputManager(t *testing.T) {
	globalFlags := &types.GlobalFlags{
		Config:           "/tmp/test.yml",
		Database:         "/tmp/test.kdbx",
		Keyfile:          "/tmp/test.keyfile",
		IgnoreConfigFile: true,
		Verbose:          false,
	}
	commandFlags := &types.CommandFlags{
		TemplateName: config.SecretsYMLFilename,
	}
	validatorMgr := validator.NewManager()
	configMgr := config.NewManager(globalFlags, commandFlags, validatorMgr)
	loggerMgr := logger.NewManager(false)
	promptMgr := prompt.NewManager()

	// Use real OutputManager to ensure integration works
	outputMgr := output.NewManager()
	secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr, newMockKeePassManager(), outputMgr, newMockTemplateManager(), validator.NewManager())

	// This should not panic or error - output goes to stdout
	err := secretsMgr.ShowTemplate()
	if err != nil {
		t.Fatalf("ShowTemplate() with real OutputManager failed: %v", err)
	}
}
