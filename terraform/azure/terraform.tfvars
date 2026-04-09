# Partial values only. `environment` and `allowed_management_cidrs` are
# deliberately omitted to test how each scanner handles unresolved variables.

location     = "eastus2"
project_name = "iac-bakeoff"

tags = {
  Project = "iac-bakeoff"
  Owner   = "platform-security"
}
