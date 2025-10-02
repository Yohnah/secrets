package git_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/git"
)

func TestRepositoryManager_IsGitRepository(t *testing.T) {
	tests := []struct {
		name           string
		setupDir       func() (string, func())
		expectedResult bool
	}{
		{
			name: "current directory is git repository",
			setupDir: func() (string, func()) {
				// We're already in a git repository, so this should return true
				return "", func() {}
			},
			expectedResult: true,
		},
		{
			name: "directory without git",
			setupDir: func() (string, func()) {
				tempDir, err := os.MkdirTemp("", "test-no-git-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				originalDir, err := os.Getwd()
				if err != nil {
					t.Fatalf("Failed to get current dir: %v", err)
				}

				err = os.Chdir(tempDir)
				if err != nil {
					t.Fatalf("Failed to change to temp dir: %v", err)
				}

				return tempDir, func() {
					os.Chdir(originalDir)
					os.RemoveAll(tempDir)
				}
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, cleanup := tt.setupDir()
			defer cleanup()

			repoMgr := git.NewRepositoryManager()
			result := repoMgr.IsGitRepository()

			if result != tt.expectedResult {
				t.Errorf("IsGitRepository() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

func TestRepositoryManager_FindGitRoot(t *testing.T) {
	tests := []struct {
		name        string
		setupDir    func() (string, func())
		expectError bool
	}{
		{
			name: "current directory is git repository",
			setupDir: func() (string, func()) {
				return "", func() {}
			},
			expectError: false,
		},
		{
			name: "directory without git",
			setupDir: func() (string, func()) {
				tempDir, err := os.MkdirTemp("", "test-no-git-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				originalDir, err := os.Getwd()
				if err != nil {
					t.Fatalf("Failed to get current dir: %v", err)
				}

				err = os.Chdir(tempDir)
				if err != nil {
					t.Fatalf("Failed to change to temp dir: %v", err)
				}

				return tempDir, func() {
					os.Chdir(originalDir)
					os.RemoveAll(tempDir)
				}
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, cleanup := tt.setupDir()
			defer cleanup()

			repoMgr := git.NewRepositoryManager()
			gitRoot, err := repoMgr.FindGitRoot()

			if tt.expectError {
				if err == nil {
					t.Errorf("FindGitRoot() expected error, got nil")
				}
				if gitRoot != "" {
					t.Errorf("FindGitRoot() expected empty string on error, got %s", gitRoot)
				}
			} else {
				if err != nil {
					t.Errorf("FindGitRoot() unexpected error: %v", err)
				}
				if gitRoot == "" {
					t.Errorf("FindGitRoot() expected non-empty string, got empty")
				}
			}
		})
	}
}

func TestRepositoryManager_EnsureGitIgnore(t *testing.T) {
	tests := []struct {
		name            string
		gitRoot         string
		pathToIgnore    string
		existingContent string
		expectError     bool
		expectedFinal   string
	}{
		{
			name:         "empty git root",
			gitRoot:      "",
			pathToIgnore: ".secrets_yohnah",
			expectError:  true,
		},
		{
			name:         "empty path to ignore",
			gitRoot:      "/tmp/test",
			pathToIgnore: "",
			expectError:  true,
		},
		{
			name:            "add to new gitignore",
			gitRoot:         "/tmp/test",
			pathToIgnore:    ".secrets_yohnah",
			existingContent: "",
			expectError:     false,
			expectedFinal:   ".secrets_yohnah\n",
		},
		{
			name:            "add to existing gitignore",
			gitRoot:         "/tmp/test",
			pathToIgnore:    ".secrets_yohnah",
			existingContent: "*.log\nnode_modules/",
			expectError:     false,
			expectedFinal:   "*.log\nnode_modules/\n.secrets_yohnah\n",
		},
		{
			name:            "path already exists",
			gitRoot:         "/tmp/test",
			pathToIgnore:    ".secrets_yohnah",
			existingContent: "*.log\n.secrets_yohnah\nnode_modules/",
			expectError:     false,
			expectedFinal:   "*.log\n.secrets_yohnah\nnode_modules/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.gitRoot != "" && !tt.expectError {
				// Create temporary directory for testing
				tempDir, err := os.MkdirTemp("", "test-gitignore-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}
				defer os.RemoveAll(tempDir)

				// Create .gitignore with existing content if provided
				gitignorePath := filepath.Join(tempDir, ".gitignore")
				if tt.existingContent != "" {
					err = os.WriteFile(gitignorePath, []byte(tt.existingContent), 0o644)
					if err != nil {
						t.Fatalf("Failed to create test .gitignore: %v", err)
					}
				}

				repoMgr := git.NewRepositoryManager()
				err = repoMgr.EnsureGitIgnore(tempDir, tt.pathToIgnore)

				if err != nil {
					t.Errorf("EnsureGitIgnore() unexpected error: %v", err)
				}

				// Verify final content
				finalContent, err := os.ReadFile(gitignorePath)
				if err != nil {
					t.Errorf("Failed to read final .gitignore: %v", err)
				}

				if string(finalContent) != tt.expectedFinal {
					t.Errorf("EnsureGitIgnore() final content = %q, want %q",
						string(finalContent), tt.expectedFinal)
				}
			} else {
				repoMgr := git.NewRepositoryManager()
				err := repoMgr.EnsureGitIgnore(tt.gitRoot, tt.pathToIgnore)

				if tt.expectError {
					if err == nil {
						t.Errorf("EnsureGitIgnore() expected error, got nil")
					}
				} else {
					if err != nil {
						t.Errorf("EnsureGitIgnore() unexpected error: %v", err)
					}
				}
			}
		})
	}
}
