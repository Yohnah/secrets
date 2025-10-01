package test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yohnah/secrets/internal/cli"
)

// TestSnapshotManagement tests the snapshot management functionality
func TestSnapshotManagement(t *testing.T) {
	logger := cli.NewLogger(false) // Silent for tests
	keepassManager := cli.NewKeePassManager(logger)
	
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.kdbx")
	keyfilePath := filepath.Join(tempDir, "test.keyfile")
	password := "testpassword123"
	profile := "test-profile"
	
	// Setup: Create database and keyfile
	err := keepassManager.GenerateKeyfile(keyfilePath)
	if err != nil {
		t.Fatalf("Failed to generate keyfile: %v", err)
	}
	
	err = keepassManager.CreateDatabase(dbPath, keyfilePath, password)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	
	// Ensure profile structure exists
	err = keepassManager.EnsureProfileStructure(dbPath, keyfilePath, password, profile)
	if err != nil {
		t.Fatalf("Failed to ensure profile structure: %v", err)
	}
	
	// Test 1: List snapshots from empty profile (should only have HEAD)
	t.Run("ListSnapshotsEmptyProfile", func(t *testing.T) {
		snapshots, err := keepassManager.ListSnapshots(dbPath, keyfilePath, password, profile)
		if err != nil {
			t.Fatalf("Failed to list snapshots: %v", err)
		}
		
		if len(snapshots) != 1 {
			t.Errorf("Expected 1 snapshot (HEAD), got %d", len(snapshots))
		}
		
		if snapshots[0] != "HEAD" {
			t.Errorf("Expected snapshot 'HEAD', got '%s'", snapshots[0])
		}
	})
	
	// Test 2: Create snapshots and verify they appear in list
	t.Run("CreateAndListSnapshots", func(t *testing.T) {
		// Create first snapshot
		result, err := keepassManager.CreateSnapshot(dbPath, keyfilePath, password, profile)
		if err != nil {
			t.Fatalf("Failed to create first snapshot: %v", err)
		}
		
		// Verify snapshot creation result
		if result.CreatedVersion == "" {
			t.Error("Expected created version to be set")
		}
		if result.NewHeadVersion == "" {
			t.Error("Expected new HEAD version to be set")
		}
		
		// List snapshots after first creation
		snapshots, err := keepassManager.ListSnapshots(dbPath, keyfilePath, password, profile)
		if err != nil {
			t.Fatalf("Failed to list snapshots after first creation: %v", err)
		}
		
		if len(snapshots) != 2 {
			t.Errorf("Expected 2 snapshots after first creation, got %d", len(snapshots))
		}
		
		// Should contain HEAD and v1
		expectedSnapshots := []string{"HEAD", "v1"}
		if !containsAll(snapshots, expectedSnapshots) {
			t.Errorf("Expected snapshots %v, got %v", expectedSnapshots, snapshots)
		}
		
		// Create second snapshot
		_, err = keepassManager.CreateSnapshot(dbPath, keyfilePath, password, profile)
		if err != nil {
			t.Fatalf("Failed to create second snapshot: %v", err)
		}
		
		// List snapshots after second creation
		snapshots, err = keepassManager.ListSnapshots(dbPath, keyfilePath, password, profile)
		if err != nil {
			t.Fatalf("Failed to list snapshots after second creation: %v", err)
		}
		
		if len(snapshots) != 3 {
			t.Errorf("Expected 3 snapshots after second creation, got %d", len(snapshots))
		}
		
		// Should contain HEAD, v1, and v2
		expectedSnapshots = []string{"HEAD", "v1", "v2"}
		if !containsAll(snapshots, expectedSnapshots) {
			t.Errorf("Expected snapshots %v, got %v", expectedSnapshots, snapshots)
		}
	})
	
	// Test 3: Delete snapshot and verify it's removed from list
	t.Run("DeleteAndListSnapshots", func(t *testing.T) {
		// First verify we have 3 snapshots
		snapshots, err := keepassManager.ListSnapshots(dbPath, keyfilePath, password, profile)
		if err != nil {
			t.Fatalf("Failed to list snapshots before deletion: %v", err)
		}
		
		if len(snapshots) != 3 {
			t.Errorf("Expected 3 snapshots before deletion, got %d", len(snapshots))
		}
		
		// Delete v1 snapshot
		err = keepassManager.DeleteSnapshot(dbPath, keyfilePath, password, profile, "v1")
		if err != nil {
			t.Fatalf("Failed to delete snapshot v1: %v", err)
		}
		
		// List snapshots after deletion
		snapshots, err = keepassManager.ListSnapshots(dbPath, keyfilePath, password, profile)
		if err != nil {
			t.Fatalf("Failed to list snapshots after deletion: %v", err)
		}
		
		if len(snapshots) != 2 {
			t.Errorf("Expected 2 snapshots after deletion, got %d", len(snapshots))
		}
		
		// Should contain HEAD and v2, but not v1
		expectedSnapshots := []string{"HEAD", "v2"}
		if !containsAll(snapshots, expectedSnapshots) {
			t.Errorf("Expected snapshots %v, got %v", expectedSnapshots, snapshots)
		}
		
		// Verify v1 is not in the list
		for _, snapshot := range snapshots {
			if snapshot == "v1" {
				t.Error("Snapshot v1 should have been deleted but still appears in list")
			}
		}
	})
	
	// Test 4: List snapshots with wrong credentials should fail
	t.Run("ListSnapshotsWrongPassword", func(t *testing.T) {
		_, err := keepassManager.ListSnapshots(dbPath, keyfilePath, "wrongpassword", profile)
		if err == nil {
			t.Error("Expected error when listing snapshots with wrong password")
		}
	})
	
	// Test 5: List snapshots for non-existent profile should fail
	t.Run("ListSnapshotsNonExistentProfile", func(t *testing.T) {
		_, err := keepassManager.ListSnapshots(dbPath, keyfilePath, password, "non-existent-profile")
		if err == nil {
			t.Error("Expected error when listing snapshots for non-existent profile")
		}
	})
	
	// Test 6: List snapshots with non-existent database should fail
	t.Run("ListSnapshotsNonExistentDatabase", func(t *testing.T) {
		nonExistentDB := filepath.Join(tempDir, "non-existent.kdbx")
		_, err := keepassManager.ListSnapshots(nonExistentDB, keyfilePath, password, profile)
		if err == nil {
			t.Error("Expected error when listing snapshots from non-existent database")
		}
	})
}

// Helper function to check if a slice contains all expected elements
func containsAll(actual []string, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	
	actualMap := make(map[string]bool)
	for _, item := range actual {
		actualMap[item] = true
	}
	
	for _, expectedItem := range expected {
		if !actualMap[expectedItem] {
			return false
		}
	}
	
	return true
}

// TestSnapshotCLICommands tests the CLI commands for snapshot management
func TestSnapshotCLICommands(t *testing.T) {
	// Test 1: Verify snapshot command structure
	t.Run("SnapshotCommandStructure", func(t *testing.T) {
		app := cli.NewApp()
		
		// Create a temporary CLI app for testing
		cliApp, ok := app.(*cli.CLIApp)
		if !ok {
			t.Fatal("Failed to cast app to CLIApp")
		}
		
		// Create snapshot command
		snapshotCmd := cli.NewSnapshotCommand(cliApp)
		
		// Verify command exists
		if snapshotCmd == nil {
			t.Error("Snapshot command should not be nil")
		}
		
		// Verify subcommands exist
		subCommands := snapshotCmd.Commands()
		expectedSubCommands := []string{"new", "delete", "list"}
		
		if len(subCommands) != len(expectedSubCommands) {
			t.Errorf("Expected %d subcommands, got %d", len(expectedSubCommands), len(subCommands))
		}
		
		// Check each expected subcommand exists
		foundCommands := make(map[string]bool)
		for _, cmd := range subCommands {
			// Extract the base command name (before any spaces/arguments)
			cmdName := cmd.Use
			if spaceIndex := strings.Index(cmdName, " "); spaceIndex != -1 {
				cmdName = cmdName[:spaceIndex]
			}
			foundCommands[cmdName] = true
		}
		
		for _, expectedCmd := range expectedSubCommands {
			if !foundCommands[expectedCmd] {
				t.Errorf("Expected subcommand '%s' not found", expectedCmd)
			}
		}
	})
	
	// Test 2: Verify list command properties
	t.Run("ListCommandProperties", func(t *testing.T) {
		app := cli.NewApp()
		cliApp, ok := app.(*cli.CLIApp)
		if !ok {
			t.Fatal("Failed to cast app to CLIApp")
		}
		
		// Create list command
		listCmd := cli.NewSnapshotListCommand(cliApp)
		
		// Verify command properties
		if listCmd.Use != "list" {
			t.Errorf("Expected command use 'list', got '%s'", listCmd.Use)
		}
		
		if listCmd.Short == "" {
			t.Error("List command should have a short description")
		}
		
		if listCmd.RunE == nil && listCmd.Run == nil {
			t.Error("List command should have a Run or RunE function")
		}
	})
}