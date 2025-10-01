package git

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Yohnah/secrets/internal/logger"
)

func TestDefaultRootFinder(t *testing.T) {
	log := logger.New(false)
	finder := NewRootFinder(log)
	
	t.Run("FindGitRoot_InCurrentDir", func(t *testing.T) {
		// Save current directory
		originalDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Failed to get current dir: %v", err)
		}
		defer os.Chdir(originalDir)
		
		// Create temporary directory structure with .git
		tmpDir, err := os.MkdirTemp("", "git_test")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)
		
		// Create .git directory
		gitDir := filepath.Join(tmpDir, ".git")
		err = os.Mkdir(gitDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create .git dir: %v", err)
		}
		
		// Change to git directory
		err = os.Chdir(tmpDir)
		if err != nil {
			t.Fatalf("Failed to change dir: %v", err)
		}
		
		// Test from git directory
		root, err := finder.FindGitRoot()
		if err != nil {
			t.Fatalf("FindGitRoot failed: %v", err)
		}
		
		if root != tmpDir {
			t.Errorf("Expected git root %s, got %s", tmpDir, root)
		}
	})
	
	t.Run("FindGitRoot_NoGitRepo", func(t *testing.T) {
		// Save current directory
		originalDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Failed to get current dir: %v", err)
		}
		defer os.Chdir(originalDir)
		
		// Create a temporary directory without .git
		tmpDir, err := os.MkdirTemp("", "nogit_test")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)
		
		// Change to non-git directory
		err = os.Chdir(tmpDir)
		if err != nil {
			t.Fatalf("Failed to change dir: %v", err)
		}
		
		_, err = finder.FindGitRoot()
		if err == nil {
			t.Error("Expected error when no git repository found")
		}
	})
	
	t.Run("RootFinderInterface", func(t *testing.T) {
		// Test that our finder implements the RootFinder interface
		var f RootFinder = NewRootFinder(log)
		
		// This should compile without issues
		_, _ = f.FindGitRoot()
	})
}