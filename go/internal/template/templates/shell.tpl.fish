{{- /* 
============================================================================
Fish Shell Environment Variables Template
----------------------------------------------------------------------------
This template generates a Fish shell script that exports environment variables
using the set -x command. It is used to inject secrets into Fish shell sessions
or scripts in a secure and automated way.

Usage:
  - Each key/value pair in the secrets map will be exported as an environment
    variable using the set -x command.
  - The template expects a map structure: { KEY: VALUE, ... }
  - Example output:
      set -x DB_PASSWORD "supersecret"
      set -x API_KEY "abcdef123456"

Security:
  - Do NOT commit generated scripts with real secrets to version control.
  - Use only in trusted Fish shell environments.

----------------------------------------------------------------------------
Template logic:
  - Iterates over all key/value pairs in the input map
  - Outputs a set -x command for each variable with quoted values
============================================================================
*/ -}}

{{range $key, $value := .}}
set -x {{$key}} "{{$value}}"
{{end}}
