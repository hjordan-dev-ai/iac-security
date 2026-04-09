###############################################################################
# Storage account. PLANTED ISSUES:
#  - enable_https_traffic_only = false (HTTP allowed)
#  - public_network_access_enabled = true
#  - min_tls_version below TLS1_2
#  - infrastructure_encryption_enabled not set
#  - Container with public access type = "container"
###############################################################################

resource "azurerm_storage_account" "data" {
  name                     = "iacbakeoffdata01"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # PLANTED: HTTP allowed.
  enable_https_traffic_only = false

  # PLANTED: TLS 1.0.
  min_tls_version = "TLS1_0"

  # PLANTED: public network access enabled.
  public_network_access_enabled = true

  # PLANTED: no infrastructure_encryption_enabled = true.

  # PLANTED: no network_rules block locking down access.

  tags = var.tags
}

resource "azurerm_storage_container" "public" {
  name                  = "public-assets"
  storage_account_name  = azurerm_storage_account.data.name
  container_access_type = "container" # PLANTED: anonymous container-level read.
}
