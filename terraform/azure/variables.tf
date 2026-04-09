# NOTE: Several variables intentionally have NO default and are NOT supplied in
# terraform.tfvars. Reproduces the c7n-left/Trivy crash on blank variables.

variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus2"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  # Intentionally no default — and not in terraform.tfvars.
}

variable "project_name" {
  description = "Project name for tagging"
  type        = string
  default     = "iac-bakeoff"
}

variable "vm_admin_username" {
  description = "VM admin username"
  type        = string
  default     = "azureuser"
}

# PLANTED ISSUE: hardcoded password as default — secret in plaintext.
variable "vm_admin_password" {
  description = "VM admin password"
  type        = string
  default     = "AzureP@ssw0rd!"
  sensitive   = true
}

variable "sql_admin_username" {
  description = "SQL admin username"
  type        = string
  default     = "sqladmin"
}

# PLANTED ISSUE: another hardcoded credential default.
variable "sql_admin_password" {
  description = "SQL admin password"
  type        = string
  default     = "Sql@Password123"
  sensitive   = true
}

variable "allowed_management_cidrs" {
  description = "CIDRs allowed for management access"
  type        = list(string)
  # Intentionally no default — exercises blank-variable handling.
}

variable "tags" {
  description = "Common tags"
  type        = map(string)
  default     = {}
}
