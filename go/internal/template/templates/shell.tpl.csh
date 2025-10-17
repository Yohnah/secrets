{{- /* 
============================================================================
C Shell Environment Variables Template
----------------------------------------------------------------------------
This template generates a C shell (csh/tcsh) script that sets environment
variables using the setenv command. It is used to inject secrets into C shell
sessions or scripts in a secure and automated way.

Usage:
  - Each key/value pair in the secrets map will be set as an environment
    variable using the setenv command.
  - The template expects a map structure: { KEY: VALUE, ... }
  - Example output:
      setenv DB_PASSWORD supersecret
      setenv API_KEY abcdef123456

Security:
  - Do NOT commit generated scripts with real secrets to version control.
  - Use only in trusted C shell environments.

----------------------------------------------------------------------------
Template logic:
  - Iterates over all key/value pairs in the input map
  - Outputs a setenv command for each variable
============================================================================
*/ -}}

{{range $key, $value := .}}
setenv {{$key}} {{$value}}
{{end}}
