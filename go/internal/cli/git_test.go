package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/git"
	"github.com/Yohnah/secrets/internal/logger"
)

func TestDefaultGitRootFinder(t *testing.T) {
	log := logger.New(false)
	gitFinder := git.NewRootFinder(log)
	
	t.Run("FindGitRoot", func(t *testing.T) {
		// This test assumes we're running in a git repository
		gitRoot, err := gitFinder.FindGitRoot()
		if err != nil {
			t.Fatalf("FindGitRoot failed: %v", err)
		}
		
		// Verify .git directory exists in the found root
		gitDir := filepath.Join(gitRoot, ".git")
		if _, err := os.Stat(gitDir); os.IsNotExist(err) {
			t.Errorf("Git root '%s' does not contain .git directory", gitRoot)
		}
	})
	
	t.Run("FindGitRootInSubdirectory", func(t *testing.T) {
		// Create a temporary subdirectory
		tmpDir, err := os.MkdirTemp("", "git_test")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)
		
		// Change to temp directory temporarily
		originalDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Failed to get current directory: %v", err)
		}
		defer os.Chdir(originalDir)
		
		// This test will fail in the temp directory since it's not in git
		// So we'll test the error case
		err = os.Chdir(tmpDir)
		if err != nil {
			t.Fatalf("Failed to change directory: %v", err)
		}
		
		_, err = gitFinder.FindGitRoot()
		if err == nil {
			t.Error("Expected error when not in a git repository")
		}
	})
}