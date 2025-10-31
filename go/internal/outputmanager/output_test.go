package outputmanager

import (
	"os"
	"testing"

	"github.com/Yohnah/secrets/internal/loggermanager"
)

func TestNewStandardOutput(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	output := NewStandardOutput(logger)

	if output == nil {
		t.Error("Expected non-nil output manager")
	}
}

func TestStandardOutput_CreateDir(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	output := NewStandardOutput(logger)

	testDir := t.TempDir() + "/test-create-dir"

	err := output.CreateDir(testDir, 0700)
	if err != nil {
		t.Errorf("Failed to create directory: %v", err)
	}

	// Verify directory exists
	info, err := os.Stat(testDir)
	if err != nil {
		t.Errorf("Directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("Path exists but is not a directory")
	}
}

func TestStandardOutput_WriteFile(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	output := NewStandardOutput(logger)

	testFile := t.TempDir() + "/test-file.txt"
	content := []byte("test content")

	err := output.WriteFile(testFile, content, 0600)
	if err != nil {
		t.Errorf("Failed to write file: %v", err)
	}

	// Verify file exists and has correct content
	readContent, err := os.ReadFile(testFile)
	if err != nil {
		t.Errorf("File not created: %v", err)
	}
	if string(readContent) != string(content) {
		t.Errorf("Expected content %q, got %q", content, readContent)
	}
}
