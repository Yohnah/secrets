package main

import (
"fmt"
"os"
"github.com/Yohnah/secrets/internal/validator"
)

func main() {
if len(os.Args) < 2 {
fmt.Println("Usage: test_validator <path-to-secrets.yml>")
os.Exit(1)
}

filePath := os.Args[1]

validatorMgr := validator.NewManager()
config, errors := validatorMgr.ReadAndValidateSecretsYML(filePath)

if len(errors) > 0 {
fmt.Printf("❌ Validation FAILED with %d error(s):\n\n", len(errors))
for i, err := range errors {
fmt.Printf("  %d. %s\n", i+1, err.Error())
}
os.Exit(1)
}

fmt.Printf("✅ Validation PASSED\n")
fmt.Printf("   Profiles found: %d\n", len(config.Profiles))
for _, profile := range config.Profiles {
fmt.Printf("   - %s (environments: %d)\n", profile.Metadata.Profile, len(profile.Environments))
}
}
