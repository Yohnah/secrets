package testutils

import (
	"os"
	"runtime"
	"testing"
)

// SetHomeEnv sets the appropriate home environment variable based on OS
// Returns a cleanup function to restore the original value
// Windows: sets USERPROFILE
// Unix-like: sets HOME
func SetHomeEnv(t *testing.T, path string) func() {
	t.Helper()

	if runtime.GOOS == "windows" {
		original := os.Getenv("USERPROFILE")
		os.Setenv("USERPROFILE", path)
		return func() {
			if original == "" {
				os.Unsetenv("USERPROFILE")
			} else {
				os.Setenv("USERPROFILE", original)
			}
		}
	}

	original := os.Getenv("HOME")
	os.Setenv("HOME", path)
	return func() {
		if original == "" {
			os.Unsetenv("HOME")
		} else {
			os.Setenv("HOME", original)
		}
	}
}
