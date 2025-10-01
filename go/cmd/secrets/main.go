package main

import (
"fmt"
"os"

"github.com/Yohnah/secrets/internal/cli"
)

// Version information - injected at build time
var (
Version   = "dev"
BuildTime = "unknown"
GitCommit = "unknown"
)

func main() {
// Create CLI application with version info
app := cli.NewCLIApp(Version, BuildTime, GitCommit)

// Execute CLI
if err := app.Execute(); err != nil {
fmt.Fprintf(os.Stderr, "Error: %v\n", err)
os.Exit(1)
}
}
