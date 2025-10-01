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
	
	// Check the binary content in detail
	if len(db.Content.Meta.Binaries) > 0 {
		binary := db.Content.Meta.Binaries[0]
		fmt.Printf("=== BINARY CONTENT ANALYSIS ===\n")
		fmt.Printf("ID: %d\n", binary.ID)
		fmt.Printf("Content length: %d bytes\n", len(binary.Content))
		fmt.Printf("Content as string: '%s'\n", string(binary.Content))
		fmt.Printf("Content as bytes: %v\n", binary.Content)
		fmt.Printf("Memory Protection: %d\n", binary.MemoryProtection)
		fmt.Printf("Compressed: %v\n", binary.Compressed)
		
		// Check if content is printable ASCII
		isPrintable := true
		for _, b := range binary.Content {
			if b < 32 || b > 126 {
				if b != 10 && b != 13 { // Allow newlines
					isPrintable = false
					break
				}
			}
		}
		fmt.Printf("Is printable ASCII: %v\n", isPrintable)
	}
}