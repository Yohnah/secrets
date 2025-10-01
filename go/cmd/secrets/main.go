package main

import (
	"log"
	"os"

	"github.com/Yohnah/secrets/internal/cli"
)

// Version information - set at build time via ldflags
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

func main() {
	// Set version information before creating the app
	cli.SetVersionInfo(Version, GitCommit, BuildTime)
	
	app := cli.NewApp()

	if err := app.Execute(); err != nil {
		log.Printf("Error: %v", err)
		os.Exit(1)
	}
}