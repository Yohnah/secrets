package types

// GlobalFlags holds all global flag values
// This is in a separate package to avoid import cycles
type GlobalFlags struct {
	Verbose          bool
	Force            bool
	Database         string
	Keyfile          string
	Config           string
	SecretsFile      string
	IgnoreConfigFile bool
	IgnoreGitProject bool
	ProfileName      string
}

// CommandFlags holds all command-specific flag values
// CliMgr captures these and feeds them to ConfigMgr as raw data
type CommandFlags struct {
	// Init command flags
	ForceRecreate    bool
	NoCreateDatabase bool
	DatabaseName     string

	// Show template command flags
	Minimal bool

	// Show status command flags
	OutputFormat string
}
