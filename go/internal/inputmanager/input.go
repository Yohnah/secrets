package inputmanager

// InputManager defines the interface for collecting user inputs
type InputManager interface {
	// CLI returns the CLI input handler
	CLI() CLIHandler
	
	// EnvVars returns the environment variables handler
	EnvVars() EnvVarsHandler
	
	// ReadFile returns the file reading handler
	ReadFile() FileReader
}

// CLIHandler defines interface for command-line interactions
type CLIHandler interface {
	// GetCommand returns the command name executed by user
	GetCommand() string
	
	// GetFlag returns the value of a global flag
	GetFlag(name string) (string, error)
	
	// GetLocalFlag returns the value of a local flag for current command
	GetLocalFlag(name string) (string, error)
	
	// AskConfirmation asks user a yes/no question (interactive mode)
	// Returns true if user confirms, false otherwise
	AskConfirmation(question string) (bool, error)
	
	// AskPassword asks user for password input (hidden)
	AskPassword(prompt string) (string, error)
	
	// AskPasswordConfirm asks user for password twice and validates they match
	AskPasswordConfirm(prompt string) (string, error)
}

// EnvVarsHandler defines interface for environment variable access
type EnvVarsHandler interface {
	// Get retrieves value of environment variable
	Get(name string) (string, bool)
	
	// GetAll returns all environment variables as map
	GetAll() map[string]string
}

// FileReader defines interface for reading file contents
type FileReader interface {
	// ReadYAML reads and parses YAML file
	ReadYAML(path string) (map[string]interface{}, error)
	
	// ReadRaw reads raw file content as bytes
	ReadRaw(path string) ([]byte, error)
}

// StandardInputManager implements InputManager interface
type StandardInputManager struct {
	cli      CLIHandler
	envVars  EnvVarsHandler
	readFile FileReader
}

// NewInputManager creates a new StandardInputManager
func NewInputManager(cli CLIHandler, envVars EnvVarsHandler, readFile FileReader) InputManager {
	return &StandardInputManager{
		cli:      cli,
		envVars:  envVars,
		readFile: readFile,
	}
}

// CLI returns the CLI handler
func (m *StandardInputManager) CLI() CLIHandler {
	return m.cli
}

// EnvVars returns the environment variables handler
func (m *StandardInputManager) EnvVars() EnvVarsHandler {
	return m.envVars
}

// ReadFile returns the file reader
func (m *StandardInputManager) ReadFile() FileReader {
	return m.readFile
}
