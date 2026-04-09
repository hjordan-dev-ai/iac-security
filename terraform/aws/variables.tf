# NOTE: Several variables intentionally have NO default and are NOT supplied in
# terraform.tfvars. This reproduces the c7n-left/Trivy crash on blank variables.
# The bake-off measures how each scanner handles this condition.

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  # Intentionally no default — and not in terraform.tfvars
}

variable "project_name" {
  description = "Project name for tagging"
  type        = string
  default     = "iac-bakeoff"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.42.0.0/16"
}

variable "db_username" {
  description = "RDS master username"
  type        = string
  default     = "admin"
}

# PLANTED ISSUE: hardcoded password as default — secret in plaintext.
variable "db_password" {
  description = "RDS master password"
  type        = string
  default     = "SuperSecret123!"
  sensitive   = true
}

variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed for SSH"
  type        = list(string)
  # Intentionally no default — exercises blank-variable handling.
}

variable "tags" {
  description = "Common resource tags"
  type        = map(string)
  default     = {}
}
