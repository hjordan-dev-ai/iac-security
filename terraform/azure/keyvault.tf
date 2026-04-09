###############################################################################
# Key Vault. PLANTED ISSUES:
#  - purge_protection_enabled = false
#  - public_network_access_enabled = true
#  - soft_delete_retention_days at minimum
#  - No network_acls deny-by-default
###############################################################################

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "main" {
  name                = "iac-bakeoff-kv-01"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  # PLANTED: purge protection disabled.
  purge_protection_enabled = false

  # PLANTED: public network access enabled.
  public_network_access_enabled = true

  # PLANTED: minimum retention.
  soft_delete_retention_days = 7

  # PLANTED: no network_acls block — defaults to Allow.

  tags = var.tags
}
