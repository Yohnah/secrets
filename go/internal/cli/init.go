package cli

import (
"os"

"github.com/Yohnah/secrets/internal/config"
"github.com/Yohnah/secrets/internal/logger"
"github.com/Yohnah/secrets/internal/prompt"
"github.com/Yohnah/secrets/internal/secrets"
	"github.com/Yohnah/secrets/internal/validator"
"github.com/spf13/cobra"
)

var (
flagForceRecreate    bool
flagNoCreateDatabase bool
)

var initCmd = &cobra.Command{
Use:   "init",
Short: "Initialize a new KeePass database",
Long:  `Initialize a new KeePass database with the required structure for secrets management.`,
Run: func(cmd *cobra.Command, args []string) {
// Step 1: Get global flags (captured by Cobra)
globalFlags := GetGlobalFlags()

// Step 2: Instantiate ValidatorManager
validatorMgr := validator.NewManager()

// Step 3: Instantiate ConfigManager (with ValidatorManager injected)
configMgr := config.NewManager(globalFlags, validatorMgr)

// Step 4: Instantiate LoggerManager
loggerMgr := logger.NewManager(globalFlags.Verbose)

// Step 5: Instantiate PromptManager
promptMgr := prompt.NewManager()

// Step 6: Instantiate SecretsManager (CORE - business logic)
secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr)

// Step 7: Execute business logic (delegate all decisions to CORE)
// Pass init flags to SecretsManager
opts := secrets.InitOptions{
ForceRecreate:    flagForceRecreate,
NoCreateDatabase: flagNoCreateDatabase,
}
if err := secretsMgr.InitWithOptions(opts); err != nil {
loggerMgr.Error(err.Error())
os.Exit(1)
}
},
}

func init() {
// Add local flags specific to init command
initCmd.Flags().BoolVar(&flagForceRecreate, "force-recreate", false, "Delete existing database and keyfile, then create new ones")
initCmd.Flags().BoolVar(&flagNoCreateDatabase, "no-create-database", false, "Skip database and keyfile creation (only creates .secrets_yohnah directory and config.yml)")

// Add command to root
rootCmd.AddCommand(initCmd)
}
