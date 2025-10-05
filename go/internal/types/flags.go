package types

// GlobalFlags holds all global flag values
// This is in a separate package to avoid import cycles
type GlobalFlags struct {
	Verbose          bool
	Force            bool
	Database         string
	Keyfile          string
	Config           string
	IgnoreConfigFile bool
	IgnoreGitProject bool
	OutputFormat     string
}
