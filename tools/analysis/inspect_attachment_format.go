package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/tobischo/gokeepasslib/v3"
)

func main() {
	dbPath := "/workspaces/secrets/.secrets_yohnah/secrets.kdbx"
	keyfilePath := "/workspaces/secrets/.secrets_yohnah/secrets.keyfile"
	password := "123456"

	// Open database
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		log.Fatalf("Failed to create credentials: %v", err)
	}

	file, err := os.Open(dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer file.Close()

	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials
	decoder := gokeepasslib.NewDecoder(file)
	if err := decoder.Decode(db); err != nil {
		log.Fatalf("Failed to decode database: %v", err)
	}

	fmt.Println("=== ATTACHMENT ANALYSIS ===")
	
	// Check binaries in metadata
	fmt.Printf("Total binaries in metadata: %d\n", len(db.Content.Meta.Binaries))
	for i, binary := range db.Content.Meta.Binaries {
		fmt.Printf("\nBinary %d (ID: %d):\n", i, binary.ID)
		
		// Get content using library methods
		contentString, err := binary.GetContentString()
		if err != nil {
			fmt.Printf("  GetContentString error: %v\n", err)
		} else {
			fmt.Printf("  GetContentString: '%s'\n", contentString)
		}
		
		contentBytes, err := binary.GetContentBytes()
		if err != nil {
			fmt.Printf("  GetContentBytes error: %v\n", err)
		} else {
			fmt.Printf("  GetContentBytes length: %d bytes\n", len(contentBytes))
			fmt.Printf("  GetContentBytes: %v\n", contentBytes)
			fmt.Printf("  GetContentBytes as string: '%s'\n", string(contentBytes))
		}
		
		// Check raw content
		fmt.Printf("  Raw Content length: %d bytes\n", len(binary.Content))
		fmt.Printf("  Raw Content: %v\n", binary.Content)
		fmt.Printf("  Raw Content as string: '%s'\n", string(binary.Content))
		
		// Try base64 decode
		if len(binary.Content) > 0 {
			decoded, err := base64.StdEncoding.DecodeString(string(binary.Content))
			if err != nil {
				fmt.Printf("  Base64 decode error: %v\n", err)
			} else {
				fmt.Printf("  Base64 decoded: '%s'\n", string(decoded))
			}
		}
	}

	// Find entries with binary attachments
	fmt.Println("\n=== ENTRIES WITH ATTACHMENTS ===")
	findEntriesWithAttachments(&db.Content.Root.Groups[0], "")
}

func findEntriesWithAttachments(group *gokeepasslib.Group, path string) {
	currentPath := path
	if path != "" {
		currentPath = path + "/" + group.Name
	} else {
		currentPath = group.Name
	}

	// Check entries in current group
	for _, entry := range group.Entries {
		if len(entry.Binaries) > 0 {
			fmt.Printf("\nEntry: %s (Path: %s)\n", entry.GetTitle(), currentPath)
			for i, binaryRef := range entry.Binaries {
				fmt.Printf("  Attachment %d: Name='%s', BinaryID=%d\n", i, binaryRef.Name, binaryRef.Value.ID)
			}
		}
	}

	// Recursively check subgroups
	for _, subgroup := range group.Groups {
		findEntriesWithAttachments(&subgroup, currentPath)
	}
}