package main

import (
	"fmt"
	"os"
	"github.com/tobischo/gokeepasslib/v3"
)

func main() {
	// Test what the original content should be
	originalText := "To be completed by developer"
	originalBytes := []byte(originalText)
	
	fmt.Printf("=== ORIGINAL CONTENT ===\n")
	fmt.Printf("Text: '%s'\n", originalText)
	fmt.Printf("Length: %d bytes\n", len(originalBytes))
	fmt.Printf("Bytes: %v\n", originalBytes)
	fmt.Printf("Hex: %x\n", originalBytes)
	
	// Now check what's actually in the database
	dbPath := "/workspaces/secrets/.secrets_yohnah/secrets.kdbx"
	keyfilePath := "/workspaces/secrets/.secrets_yohnah/secrets.keyfile"
	password := "123456"
	
	credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(password, keyfilePath)
	if err != nil {
		fmt.Printf("Error creating credentials: %v\n", err)
		return
	}
	
	file, err := os.Open(dbPath)
	if err != nil {
		fmt.Printf("Error opening database: %v\n", err)
		return
	}
	defer file.Close()
	
	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials
	decoder := gokeepasslib.NewDecoder(file)
	if err := decoder.Decode(db); err != nil {
		fmt.Printf("Error decoding database: %v\n", err)
		return
	}
	
	if len(db.Content.Meta.Binaries) > 0 {
		binary := db.Content.Meta.Binaries[0]
		fmt.Printf("\n=== DATABASE CONTENT ===\n")
		fmt.Printf("Text: '%s'\n", string(binary.Content))
		fmt.Printf("Length: %d bytes\n", len(binary.Content))
		fmt.Printf("Bytes: %v\n", binary.Content)
		fmt.Printf("Hex: %x\n", binary.Content)
		
		// Check if they match
		fmt.Printf("\n=== COMPARISON ===\n")
		fmt.Printf("Lengths match: %v\n", len(originalBytes) == len(binary.Content))
		if len(originalBytes) == len(binary.Content) {
			bytesMatch := true
			for i := range originalBytes {
				if originalBytes[i] != binary.Content[i] {
					fmt.Printf("Byte %d differs: expected %d, got %d\n", i, originalBytes[i], binary.Content[i])
					bytesMatch = false
				}
			}
			fmt.Printf("All bytes match: %v\n", bytesMatch)
		}
	}
}