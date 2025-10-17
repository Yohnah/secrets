{{- /* 
============================================================================
Windows CMD Environment Variables Template
----------------------------------------------------------------------------
This template generates a Windows CMD batch script that sets environment
variables using the SET command. It is used to inject secrets into Windows
CMD sessions or scripts in a secure and automated way.

Usage:
  - Execute the script in CMD: script.cmd
  - Variables become available in the current CMD session
  - The template expects a map structure: { KEY: VALUE, ... }
  - Example output creates CMD environment variables

Security:
  - Do NOT commit generated scripts with real secrets to version control.
  - Use only in trusted Windows CMD environments.

----------------------------------------------------------------------------
Template logic:
  - Iterates over all key/value pairs in the input map
  - Outputs a SET command for each variable
============================================================================
*/ -}}

@echo off
{{range $key, $value := .}}
SET {{$key}}={{$value}}
{{end}}
