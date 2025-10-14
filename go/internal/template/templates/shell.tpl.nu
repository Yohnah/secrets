# ============================================================================
# Nushell Environment Variables Template
# ----------------------------------------------------------------------------
# This template generates a Nushell script that sets environment variables
# using the $env.VARIABLE syntax. It is used to inject secrets into Nushell
# sessions or scripts in a secure and automated way.
#
# Usage:
#   - Each key/value pair in the secrets map will be set as an environment
#     variable using the $env.VARIABLE_NAME syntax.
#   - The template expects a map structure: { KEY: VALUE, ... }
#   - Example output:
#       $env.DB_PASSWORD = "supersecret"
#       $env.API_KEY = "abcdef123456"
#
# Security:
#   - Do NOT commit generated scripts with real secrets to version control.
#   - Use only in trusted Nushell environments.
#
# ----------------------------------------------------------------------------
# Template logic:
#   - Iterates over all key/value pairs in the input map
#   - Outputs a Nushell environment variable assignment for each
# ============================================================================

{{range $key, $value := .}}
$env.{{$key}} = "{{$value}}"
{{end}}
