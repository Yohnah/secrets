# ============================================================================
# Terraform Variables Template
# ----------------------------------------------------------------------------
# This template generates a Terraform .tfvars file that can be used to
# provide variable values to Terraform configurations. It creates HCL
# variable assignments that can be referenced in .tf files.
#
# Usage:
#   - Use as terraform.tfvars or environment-specific .tfvars files
#   - Variables are automatically loaded by Terraform
#   - Reference in .tf files: var.db_password
#   - The template expects data with: { Items: map[string]string }
#   - Example output creates Terraform variable assignments
#
# Security:
#   - .tfvars files contain sensitive infrastructure secrets
#   - Use Terraform Cloud/Enterprise remote state for secrets management
#   - Do NOT commit generated files with real secrets to version control
#   - Consider using Terraform Cloud variable sets for production
#
# ----------------------------------------------------------------------------
# Template logic:
#   - Iterates over .Items map, creating variable = "value" assignments
#   - Uses HCL syntax compatible with Terraform variable files
# ============================================================================

{{range $key, $value := .Items}}
{{$key}} = "{{$value}}"
{{end}}
