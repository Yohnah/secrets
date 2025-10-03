package tools
package main

import (
	"encoding/base64"
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

	fmt.Println("=== BINARY INSPECTION ===\n")
	
	// Inspect binaries storage location
	fmt.Printf("Database KDBX Version: %d.%d\n", db.Header.Signature.MajorVersion, db.Header.Signature.MinorVersion)
	fmt.Printf("Is KDBX4: %v\n\n", db.Header.IsKdbx4())
	
	// Check InnerHeader binaries (KDBX4)
	if db.Content.InnerHeader != nil {
		fmt.Printf("InnerHeader Binaries count: %d\n", len(db.Content.InnerHeader.Binaries))
		for i, binary := range db.Content.InnerHeader.Binaries {
			contentBytes, err := binary.GetContentBytes()
			if err != nil {
				fmt.Printf("  [%d] ID=%d, Error: %v\n", i, binary.ID, err)
			} else {
				fmt.Printf("  [%d] ID=%d, Size=%d bytes, Compressed=%v, Content=\"%s\"\n", 
					i, binary.ID, len(contentBytes), binary.Compressed, string(contentBytes))
			}
		}
	}
	
	// Check Metadata binaries (KDBX3)
	fmt.Printf("\nMetadata Binaries count: %d\n", len(db.Content.Meta.Binaries))
	for i, binary := range db.Content.Meta.Binaries {
		contentBytes, err := binary.GetContentBytes()
		if err != nil {
			fmt.Printf("  [%d] ID=%d, Error: %v\n", i, binary.ID, err)
		} else {
			fmt.Printf("  [%d] ID=%d, Size=%d bytes, Compressed=%v, Content=\"%s\"\n", 
				i, binary.ID, len(contentBytes), binary.Compressed, string(contentBytes))
			
			// Show raw Content field
			if len(binary.Content) > 0 {
				fmt.Printf("       Raw Content length: %d, Base64: %s...\n", 
					len(binary.Content), base64.StdEncoding.EncodeToString(binary.Content)[:50])
			}
		}
	}
	
	// Find first entry with attachments
	fmt.Println("\n=== FIRST ENTRY WITH ATTACHMENTS ===")
	found := false
	var inspectEntry func(group gokeepasslib.Group)
	inspectEntry = func(group gokeepasslib.Group) {
		if found {
			return
		}
		for _, entry := range group.Entries {
			if len(entry.Binaries) > 0 {
				title := entry.GetTitle()
				fmt.Printf("\nEntry: %s\n", title)
				fmt.Printf("Binary References count: %d\n", len(entry.Binaries))
				for _, binRef := range entry.Binaries {
					fmt.Printf("  - Name: %s, ID: %d\n", binRef.Name, binRef.Value.ID)
					
					// Find the actual binary
					binary := db.FindBinary(binRef.Value.ID)
					if binary != nil {
						contentBytes, err := binary.GetContentBytes()
						if err != nil {
							fmt.Printf("    Error getting content: %v\n", err)
						} else {
							fmt.Printf("    Binary found: ID=%d, Size=%d bytes, Compressed=%v\n", 
								binary.ID, len(contentBytes), binary.Compressed)
							fmt.Printf("    Content: \"%s\"\n", string(contentBytes))
						}
					} else {
						fmt.Printf("    Binary NOT FOUND in database!\n")
					}
				}
				found = true
				return
			}
		}
		for _, subGroup := range group.Groups {
			inspectEntry(subGroup)
		}
	}
	
	rootGroup := &db.Content.Root.Groups[0]
	for _, profileGroup := range rootGroup.Groups {
		for _, headGroup := range profileGroup.Groups {
			for _, envGroup := range headGroup.Groups {
				inspectEntry(envGroup)
			}
		}
	}
}
