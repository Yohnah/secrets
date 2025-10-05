package main

import (
	"fmt"
	"os"

	"github.com/tobischo/gokeepasslib/v3"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: go run inspect_db.go <db_path> <keyfile_path> <password>")
		os.Exit(1)
	}

	dbPath := os.Args[1]
	keyfilePath := os.Args[2]
	password := os.Args[3]

	// Create credentials
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		fmt.Printf("Error creating credentials: %v\n", err)
		os.Exit(1)
	}

	// Open database file
	file, err := os.Open(dbPath)
	if err != nil {
		fmt.Printf("Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Create database and assign credentials
	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials

	// Decode database
	decoder := gokeepasslib.NewDecoder(file)
	err = decoder.Decode(db)
	if err != nil {
		fmt.Printf("Error decoding database: %v\n", err)
		os.Exit(1)
	}

	// Unlock protected entries
	err = db.UnlockProtectedEntries()
	if err != nil {
		fmt.Printf("Error unlocking database: %v\n", err)
		os.Exit(1)
	}

	// Inspect root group
	fmt.Println("=== KeePass Database Inspection ===")
	fmt.Println()
	fmt.Printf("Database Path: %s\n", dbPath)
	fmt.Printf("KDBX Version: %d\n", db.Header.FileVersion.MajorVersion)
	fmt.Println()

	if len(db.Content.Root.Groups) > 0 {
		rootGroup := db.Content.Root.Groups[0]
		fmt.Printf("Root Group Name: \"%s\"\n", rootGroup.Name)
		fmt.Printf("Root Group Entries Count: %d\n", len(rootGroup.Entries))
		fmt.Printf("Root Group Subgroups Count: %d\n", len(rootGroup.Groups))
		fmt.Println()

		if len(rootGroup.Entries) > 0 {
			fmt.Println("Entries in Root Group:")
			for i, entry := range rootGroup.Entries {
				fmt.Printf("  [%d] Title: \"%s\"\n", i+1, entry.GetTitle())
			}
		} else {
			fmt.Println("✓ Root Group is EMPTY (no entries)")
		}

		if len(rootGroup.Groups) > 0 {
			fmt.Println()
			fmt.Println("Subgroups in Root Group:")
			for i, group := range rootGroup.Groups {
				fmt.Printf("  [%d] Name: \"%s\" (Entries: %d)\n", i+1, group.Name, len(group.Entries))
			}
		}
	} else {
		fmt.Println("ERROR: No root group found!")
	}
}
