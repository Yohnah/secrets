package main

import (
	"fmt"
	"log"
	"os"

	"github.com/tobischo/gokeepasslib/v3"
)

func main() {
	// Paths
	dbPath := "/workspaces/secrets/.secrets_yohnah/secrets.kdbx"
	keyfilePath := "/workspaces/secrets/.secrets_yohnah/secrets.keyfile"

	// Open database
	dbFile, err := os.Open(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer dbFile.Close()

	// Decode database
	db := gokeepasslib.NewDatabase()
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials("123456", keyfilePath)
	if err != nil {
		log.Fatal("Credentials error:", err)
	}

	db.Credentials = credentials
	err = gokeepasslib.NewDecoder(dbFile).Decode(db)
	if err != nil {
		log.Fatal("Decode error:", err)
	}

	err = db.UnlockProtectedEntries()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("=== DATABASE STRUCTURE ===\n")

	// Navigate to profile
	rootGroup := &db.Content.Root.Groups[0]
	fmt.Printf("Root Group: %s\n", rootGroup.Name)

	for _, profileGroup := range rootGroup.Groups {
		fmt.Printf("  Profile: %s\n", profileGroup.Name)

		for _, headGroup := range profileGroup.Groups {
			fmt.Printf("    %s\n", headGroup.Name)

			// List environments
			for _, envGroup := range headGroup.Groups {
				fmt.Printf("      Environment: %s\n", envGroup.Name)

				// List entries in environment
				listEntriesRecursive(envGroup, "        ", db)
			}
		}
	}
}

func listEntriesRecursive(group gokeepasslib.Group, indent string, db *gokeepasslib.Database) {
	// List entries in this group
	for _, entry := range group.Entries {
		title := ""
		for _, value := range entry.Values {
			if value.Key == "Title" {
				title = value.Value.Content
				break
			}
		}

		fmt.Printf("%sEntry: %s\n", indent, title)

		// List attachments with content
		if len(entry.Binaries) > 0 {
			fmt.Printf("%s  Attachments:\n", indent)
			for _, binaryRef := range entry.Binaries {
				// Get the actual binary data from database using the reference ID
				binary := db.FindBinary(binaryRef.Value.ID)
				var content string
				if binary != nil {
					contentBytes, err := binary.GetContentBytes()
					if err != nil {
						content = fmt.Sprintf("Error reading content: %v", err)
					} else if len(contentBytes) > 100 {
						content = fmt.Sprintf("%d bytes (truncated: %s...)", len(contentBytes), string(contentBytes[:100]))
					} else {
						content = string(contentBytes)
					}
				} else {
					content = "Error: Binary not found in database"
				}
				fmt.Printf("%s    - %s: %s\n", indent, binaryRef.Name, content)
			}
		}

		// List fields with content
		fmt.Printf("%s  Fields:\n", indent)
		for _, value := range entry.Values {
			if value.Key != "Title" {
				content := value.Value.Content
				if len(content) > 100 {
					content = content[:100] + "... (truncated)"
				}
				fmt.Printf("%s    - %s: %s\n", indent, value.Key, content)
			}
		}
	}

	// Process subgroups
	for _, subGroup := range group.Groups {
		fmt.Printf("%s  Subgroup: %s\n", indent, subGroup.Name)
		listEntriesRecursive(subGroup, indent+"    ", db)
	}
}
