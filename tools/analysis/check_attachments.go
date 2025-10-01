package main

import (
	"fmt"
	"os"
	"github.com/tobischo/gokeepasslib/v3"
)

func main() {
	dbPath := "/workspaces/secrets/.secrets_yohnah/secrets.kdbx"
	keyfilePath := "/workspaces/secrets/.secrets_yohnah/secrets.keyfile"
	password := "123456"
	
	// Create credentials
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		fmt.Printf("Error creating credentials: %v\n", err)
		return
	}
	
	// Open database
	file, err := os.Open(dbPath)
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
	
	// Check binaries in metadata
	fmt.Printf("=== DATABASE BINARIES ===\n")
	fmt.Printf("Total binaries in metadata: %d\n", len(db.Content.Meta.Binaries))
	
	for i, binary := range db.Content.Meta.Binaries {
		fmt.Printf("Binary %d:\n", i)
		fmt.Printf("  ID: %d\n", binary.ID)
		fmt.Printf("  Content length: %d bytes\n", len(binary.Content))
		fmt.Printf("  Content preview: %s\n", string(binary.Content)[:min(50, len(binary.Content))])
	}
	
	// Find STAGE_SECRET entry and check its binaries
	fmt.Printf("\n=== ENTRY BINARY REFERENCES ===\n")
	checkEntryBinaries(db.Content.Root.Groups[0], 0)
}

func checkEntryBinaries(group gokeepasslib.Group, level int) {
	indent := ""
	for i := 0; i < level; i++ {
		indent += "  "
	}
	
	for _, entry := range group.Entries {
		if len(entry.Binaries) > 0 {
			fmt.Printf("%sEntry: %s\n", indent, entry.GetTitle())
			fmt.Printf("%s  Binary references: %d\n", indent, len(entry.Binaries))
			for i, binRef := range entry.Binaries {
				fmt.Printf("%s    Binary %d: Name=%s, RefID=%d\n", indent, i, binRef.Name, binRef.Value.ID)
			}
		}
	}
	
	for _, subGroup := range group.Groups {
		checkEntryBinaries(subGroup, level+1)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}