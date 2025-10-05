package cli

import (
"os"

"github.com/Yohnah/secrets/internal/config"
"github.com/Yohnah/secrets/internal/logger"
"github.com/Yohnah/secrets/internal/prompt"
"github.com/Yohnah/secrets/internal/secrets"
"github.com/spf13/cobra"
)

var (
flagForceRecreate bool
)

var initCmd = &cobra.Command{
Use:   "init",
Short: "Initialize a new KeePass database",
Long:  `Initialize a new KeePass database with the required structure for secrets management.`,
Run: func(cmd *cobra.Command, args []string) {
// Step 1: Get global flags (captured by Cobra)
globalFlags := GetGlobalFlags()

// Step 2: Instantiate ConfigManager
configMgr := config.NewManager(globalFlags)

// Step 3: Instantiate LoggerManager
loggerMgr := logger.NewManager(globalFlags.Verbose)

// Step 4: Instantiate PromptManager
promptMgr := prompt.NewManager()

// Step 5: Instantiate SecretsManager (CORE - business logic)
secretsMgr := secrets.NewManager(configMgr, loggerMgr, promptMgr)

// Step 6: Execute business logic (delegate all decisions to CORE)
// Pass the --force-recreate flag to SecretsManager
if err := secretsMgr.InitWithRecreate(flagForceRecreate); err != nil {
loggerMgr.Error(err.Error())
os.Exit(1)
}
},
}

func init() {
// Add local flag specific to init command
initCmd.Flags().BoolVar(&flagForceRecreate, "force-recreate", false, "Delete existing database and keyfile, then create new ones")

// Add command to root
rootCmd.AddCommand(initCmd)
}
