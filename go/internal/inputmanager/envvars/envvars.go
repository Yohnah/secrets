package envvars

import (
"os"
"strings"
)

type EnvVarsReader interface {
Get(key string) (string, bool)
GetAll() map[string]string
}

type OsEnvVarsReader struct{}

func NewOsEnvVarsReader() EnvVarsReader {
return &OsEnvVarsReader{}
}

func (r *OsEnvVarsReader) Get(key string) (string, bool) {
return os.LookupEnv(key)
}

func (r *OsEnvVarsReader) GetAll() map[string]string {
result := make(map[string]string)
for _, env := range os.Environ() {
parts := strings.SplitN(env, "=", 2)
if len(parts) == 2 {
result[parts[0]] = parts[1]
}
}
return result
}
