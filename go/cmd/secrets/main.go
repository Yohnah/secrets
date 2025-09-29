package main

import (
	"log"
	"os"

	"github.com/Yohnah/secrets/internal/cli"
)

func main() {
	// Crear la aplicación CLI
	app := cli.NewCLIApp()

	// Ejecutar y manejar errores
	if err := app.Execute(); err != nil {
		log.Printf("Error: %v", err)
		os.Exit(1)
	}
}