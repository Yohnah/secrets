{{- /* 
============================================================================
Shell Environment Export Template
----------------------------------------------------------------------------
This template generates a shell script that exports all secrets as environment
variables. It is used to inject secrets into shell sessions or scripts in a
secure and automated way.

Usage:
  - Each key/value pair in the secrets map will be exported as an environment
    variable in the shell.
  - The template expects a map structure: { KEY: VALUE, ... }
  - Example output:
      export DB_PASSWORD="supersecret"
      export API_KEY="abcdef123456"

Security:
  - Do NOT commit generated scripts with real secrets to version control.
  - Use only in trusted environments.

----------------------------------------------------------------------------
Template logic:
  - Iterates over all key/value pairs in the input map
  - Outputs an export statement for each
============================================================================
*/ -}}

{{range $key, $value := .}}
export {{$key}}="{{$value}}"
{{end}}
