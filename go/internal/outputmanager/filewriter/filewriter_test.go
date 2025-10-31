package filewriter

import (
	"os"
	"testing"

	"github.com/Yohnah/secrets/internal/loggermanager"
)

func TestNewFileSystemWriter(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	writer := NewFileSystemWriter(logger)

	if writer == nil {
		t.Error("Expected non-nil file writer")
	}
}

func TestFileSystemWriter_CreateDirectory(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	writer := NewFileSystemWriter(logger)

	testDir := t.TempDir() + "/test-dir"

	err := writer.CreateDirectory(testDir, 0700)
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

	// Test creating existing directory (should not error)
	err = writer.CreateDirectory(testDir, 0700)
	if err != nil {
		t.Errorf("Expected no error for existing directory, got: %v", err)
	}
}

func TestFileSystemWriter_CreateDirectory_FileExists(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	writer := NewFileSystemWriter(logger)

	// Create a file first
	testFile := t.TempDir() + "/test-file"
	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Try to create directory with same name
	err := writer.CreateDirectory(testFile, 0700)
	if err == nil {
		t.Error("Expected error when path exists as file")
	}
}

func TestFileSystemWriter_WriteFile(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	writer := NewFileSystemWriter(logger)

	testFile := t.TempDir() + "/subdir/test-file.txt"
	content := []byte("test content")

	err := writer.WriteFile(testFile, content, 0600)
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

func TestFileSystemWriter_WriteFile_CreatesParentDir(t *testing.T) {
	logger := loggermanager.NewStderrLogger()
	writer := NewFileSystemWriter(logger)

	testFile := t.TempDir() + "/parent/child/test.txt"
	content := []byte("test")

	err := writer.WriteFile(testFile, content, 0600)
	if err != nil {
		t.Errorf("Failed to write file with nested parents: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(testFile); err != nil {
		t.Errorf("File not created: %v", err)
	}
}
