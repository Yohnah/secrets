package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: debugyaml <file>")
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read error: %v\n", err)
		os.Exit(1)
	}

	var v interface{}
	if err := yaml.Unmarshal(data, &v); err != nil {
		fmt.Fprintf(os.Stderr, "yaml error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("ok")
}
