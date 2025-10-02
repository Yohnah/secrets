package cli

type GlobalFlags struct {
	Config          string
	Database        string
	Keyfile         string
	SecretsConfig   string
	Password        string
	Verbose         bool
	Force           bool
	IgnoreGitRepo   bool
}