###############################################################################
# Azure SQL. PLANTED ISSUES:
#  - public_network_access_enabled = true
#  - Firewall rule 0.0.0.0 - 255.255.255.255 (allow all)
#  - No transparent_data_encryption block on the database
#  - No threat detection / auditing policy
#  - SQL admin password from hardcoded variable default
###############################################################################

resource "azurerm_mssql_server" "main" {
  name                         = "${var.project_name}-sql-${var.environment}"
  resource_group_name          = azurerm_resource_group.main.name
  location                     = azurerm_resource_group.main.location
  version                      = "12.0"
  administrator_login          = var.sql_admin_username
  administrator_login_password = var.sql_admin_password

  # PLANTED: public network access enabled.
  public_network_access_enabled = true

  # PLANTED: no minimum_tls_version explicitly enforced.

  tags = var.tags
}

# PLANTED: firewall rule allowing the entire IPv4 address space.
resource "azurerm_mssql_firewall_rule" "allow_all" {
  name             = "AllowAll"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_mssql_database" "appdb" {
  name      = "appdb"
  server_id = azurerm_mssql_server.main.id
  sku_name  = "S0"

  # PLANTED: no transparent_data_encryption block (TDE not explicitly enabled).
  # PLANTED: no threat detection / extended auditing policy.
}

# PLANTED: no azurerm_mssql_server_security_alert_policy resource.
# PLANTED: no azurerm_mssql_server_extended_auditing_policy resource.
