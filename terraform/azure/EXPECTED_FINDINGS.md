# Azure Stack — Ground-Truth Planted Issues

20 manufactured misconfigurations seeded across the Azure mini-stack.

| # | File | Resource | Category | Issue | Expected check IDs |
|---|---|---|---|---|---|
| 1 | main.tf | azurerm_network_security_group.app | network | SSH (22) open to Internet | CKV_AZURE_10, AVD-AZU-0050 |
| 2 | main.tf | azurerm_network_security_group.app | network | RDP (3389) open to Internet | CKV_AZURE_9, AVD-AZU-0048 |
| 3 | main.tf | (account) | logging | No NSG flow logs | CKV_AZURE_12 |
| 4 | main.tf | azurerm_virtual_network.main | network | No DDoS protection plan | CKV_AZURE_183 |
| 5 | compute.tf | azurerm_public_ip.app | exposure | VM has public IP | CKV_AZURE_119 |
| 6 | compute.tf | azurerm_linux_virtual_machine.app | iam | Password authentication enabled | CKV_AZURE_178, CKV_AZURE_149 |
| 7 | compute.tf | azurerm_linux_virtual_machine.app | secret | Admin password from hardcoded variable default | CKV_SECRET_6 |
| 8 | compute.tf | azurerm_linux_virtual_machine.app | encryption | OS disk not encrypted with CMK | CKV_AZURE_151 |
| 9 | compute.tf | azurerm_linux_virtual_machine.app | logging | Boot diagnostics not enabled | CKV_AZURE_50 |
| 10 | storage.tf | azurerm_storage_account.data | encryption | enable_https_traffic_only = false | CKV_AZURE_3, AVD-AZU-0007 |
| 11 | storage.tf | azurerm_storage_account.data | exposure | public_network_access_enabled = true | CKV_AZURE_35, CKV_AZURE_59 |
| 12 | storage.tf | azurerm_storage_account.data | encryption | min_tls_version = TLS1_0 | CKV_AZURE_44 |
| 13 | storage.tf | azurerm_storage_account.data | encryption | infrastructure_encryption not enabled | CKV_AZURE_146 |
| 14 | storage.tf | azurerm_storage_container.public | exposure | container_access_type = "container" | CKV_AZURE_34 |
| 15 | keyvault.tf | azurerm_key_vault.main | governance | purge_protection_enabled = false | CKV_AZURE_42, CKV_AZURE_110 |
| 16 | keyvault.tf | azurerm_key_vault.main | exposure | public_network_access_enabled = true | CKV_AZURE_109, CKV_AZURE_189 |
| 17 | keyvault.tf | azurerm_key_vault.main | governance | No network_acls deny-by-default | CKV_AZURE_109 |
| 18 | sql.tf | azurerm_mssql_server.main | exposure | public_network_access_enabled = true | CKV_AZURE_113 |
| 19 | sql.tf | azurerm_mssql_firewall_rule.allow_all | network | Firewall rule 0.0.0.0–255.255.255.255 | CKV_AZURE_11 |
| 20 | sql.tf | azurerm_mssql_database.appdb | logging | No threat detection / auditing policy | CKV_AZURE_24, CKV_AZURE_27, CKV_AZURE_25 |
| 21 | sql.tf | azurerm_mssql_database.appdb | encryption | No explicit TDE block | CKV_AZURE_28 |

## Tfvars repro

`variables.tf` declares `environment` and `allowed_management_cidrs` with no
default, and `terraform.tfvars` does not provide values for them. Same
condition as the AWS stack — see `terraform/aws/EXPECTED_FINDINGS.md` for the
grading criteria.
