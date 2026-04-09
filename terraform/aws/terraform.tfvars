# Partial values only. `environment` and `allowed_ssh_cidrs` are deliberately
# omitted to test how each scanner handles unresolved variable references.
# Some legacy pipelines also reference an `extra.tfvars` file that does not
# exist in this repo — this is the c7n-left repro.

region       = "us-east-2"
project_name = "iac-bakeoff"
vpc_cidr     = "10.42.0.0/16"

tags = {
  Project = "iac-bakeoff"
  Owner   = "platform-security"
}
