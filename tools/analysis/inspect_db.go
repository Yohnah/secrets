package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/tobischo/gokeepasslib/v3"
)

func main() {
	// Parse command line arguments
	dbPath := flag.String("db", "../.secrets_yohnah/secrets.kdbx", "Path to the KeePass database")
	keyfilePath := flag.String("keyfile", "../.secrets_yohnah/secrets.keyfile", "Path to the keyfile")
	password := flag.String("password", "123456", "Database password")
	flag.Parse()

	fmt.Printf("Using database: %s\n", *dbPath)
	fmt.Printf("Using password: %s\n", *password)

	// Create credentials - only use keyfile if it's not the default and exists
	var credentials *gokeepasslib.DBCredentials
	var err error
	
	if *keyfilePath != "../.secrets_yohnah/secrets.keyfile" && *keyfilePath != "" && fileExists(*keyfilePath) {
		fmt.Printf("Using keyfile: %s\n", *keyfilePath)
		credentials, err = gokeepasslib.NewPasswordAndKeyCredentials(*password, *keyfilePath)
	} else {
		fmt.Println("Using only password (no keyfile)")
		credentials = gokeepasslib.NewPasswordCredentials(*password)
	}
	
	if err != nil {
		fmt.Printf("Error creating credentials: %v\n", err)
		return
	}

	// Open database
	file, err := os.Open(*dbPath)
	if err != nil {
		fmt.Printf("Error opening database: %v\n", err)
		return
	}
	defer file.Close()

	// Decode database
	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials
	decoder := gokeepasslib.NewDecoder(file)
	if err := decoder.Decode(db); err != nil {
		fmt.Printf("Error decoding database: %v\n", err)
		return
	}

	// Print structure
	fmt.Println("=== DATABASE STRUCTURE ===")
	fmt.Printf("Root groups count: %d\n", len(db.Content.Root.Groups))
	
	// Show binaries metadata
	if len(db.Content.Meta.Binaries) > 0 {
		fmt.Printf("Binaries in metadata: %d\n", len(db.Content.Meta.Binaries))
		for i, binary := range db.Content.Meta.Binaries {
			fmt.Printf("  Binary %d: ID=%d, Size=%d bytes\n", i+1, binary.ID, len(binary.Content))
			content, err := binary.GetContentString()
			if err != nil {
				fmt.Printf("    Content: <error reading: %v>\n", err)
			} else {
				if len(content) > 100 {
					fmt.Printf("    Content preview: %.100s...\n", content)
				} else {
					fmt.Printf("    Content: %s\n", content)
				}
			}
		}
		fmt.Println()
	}
	
	for i, group := range db.Content.Root.Groups {
		fmt.Printf("Root Group %d: %s (UUID: %s)\n", i+1, group.Name, group.UUID)
		
		// Show entries in root group
		fmt.Printf("  Entries count: %d\n", len(group.Entries))
		for j, entry := range group.Entries {
			fmt.Printf("  Entry %d: %s\n", j+1, entry.GetTitle())
			fmt.Printf("    Fields:\n")
			for _, value := range entry.Values {
				fmt.Printf("      %s: %s\n", value.Key, value.Value.Content)
			}
			
			// Show attachments/binaries
			if len(entry.Binaries) > 0 {
				fmt.Printf("    Attachments:\n")
				for k, binaryRef := range entry.Binaries {
					fmt.Printf("      Attachment %d: %s -> Binary ID %d\n", k+1, binaryRef.Name, binaryRef.Value.ID)
				}
			}
		}
		
		printSubGroups(group, 1)
	}
}

func printSubGroups(group gokeepasslib.Group, level int) {
	indent := ""
	for i := 0; i < level; i++ {
		indent += "  "
	}
	
	for i, subGroup := range group.Groups {
		fmt.Printf("%sSubGroup %d: %s (UUID: %s)\n", indent, i+1, subGroup.Name, subGroup.UUID)
		fmt.Printf("%s  Entries count: %d\n", indent, len(subGroup.Entries))
		for j, entry := range subGroup.Entries {
			fmt.Printf("%s  Entry %d: %s\n", indent, j+1, entry.GetTitle())
			fmt.Printf("%s    Fields:\n", indent)
			for _, value := range entry.Values {
				fmt.Printf("%s      %s: %s\n", indent, value.Key, value.Value.Content)
			}
			
			// Show attachments/binaries
			if len(entry.Binaries) > 0 {
				fmt.Printf("%s    Attachments:\n", indent)
				for k, binaryRef := range entry.Binaries {
					fmt.Printf("%s      Attachment %d: %s -> Binary ID %d\n", indent, k+1, binaryRef.Name, binaryRef.Value.ID)
				}
			}
		}
		printSubGroups(subGroup, level+1)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}