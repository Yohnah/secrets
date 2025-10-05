package main

import (
"os"

"github.com/Yohnah/secrets/internal/cli"
)

func main() {
if err := cli.Execute(); err != nil {
os.Exit(1)
}
}
