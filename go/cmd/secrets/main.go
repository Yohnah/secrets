package main

import (
"log"
"os"

"github.com/Yohnah/secrets/internal/cli"
)

func main() {
app := cli.NewApp()

if err := app.Execute(); err != nil {
log.Printf("Error: %v", err)
os.Exit(1)
}
}
