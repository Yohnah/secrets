package inputmanager

type InputManager interface {
CLI() CLIHandler
EnvVars() EnvVarsHandler
ReadFile() FileReader
Prompts() PromptsHandler
}

type CLIHandler interface {
GetCommand() string
GetStringFlag(name string) (string, error)
GetBoolFlag(name string) (bool, error)
}

type PromptsHandler interface {
AskConfirmation(prompt string, defaultValue bool) (bool, error)
AskPassword(prompt string) (string, error)
AskPasswordConfirm(prompt string) (string, error)
AskText(prompt string) (string, error)
AskChoice(prompt string, options []string) (string, error)
}

type EnvVarsHandler interface {
Get(name string) (string, bool)
GetAll() map[string]string
}

type FileReader interface {
ReadYAML(path string) (map[string]interface{}, error)
ReadRaw(path string) ([]byte, error)
}

type StandardInputManager struct {
cli      CLIHandler
envVars  EnvVarsHandler
readFile FileReader
prompts  PromptsHandler
}

func NewInputManager(cli CLIHandler, envVars EnvVarsHandler, readFile FileReader, prompts PromptsHandler) InputManager {
return &StandardInputManager{
cli:      cli,
envVars:  envVars,
readFile: readFile,
prompts:  prompts,
}
}

func (m *StandardInputManager) CLI() CLIHandler {
return m.cli
}

func (m *StandardInputManager) EnvVars() EnvVarsHandler {
return m.envVars
}

func (m *StandardInputManager) ReadFile() FileReader {
return m.readFile
}

func (m *StandardInputManager) Prompts() PromptsHandler {
return m.prompts
}
