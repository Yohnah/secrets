package main

import (
	"fmt"
	"os"

	"github.com/Yohnah/secrets/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
}
