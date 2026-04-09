###############################################################################
# Linux VM. PLANTED ISSUES:
#  - VM has a public IP attached
#  - Password authentication enabled (disable_password_authentication = false)
#  - admin_password sourced from variable with hardcoded default
#  - OS disk not encrypted with customer-managed key
#  - Boot diagnostics not configured
###############################################################################

# PLANTED: public IP on VM.
resource "azurerm_public_ip" "app" {
  name                = "${var.project_name}-app-pip"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_interface" "app" {
  name                = "${var.project_name}-app-nic"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = var.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.app.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.app.id
  }
}

resource "azurerm_linux_virtual_machine" "app" {
  name                = "${var.project_name}-app-vm"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  size                = "Standard_B2s"
  admin_username      = var.vm_admin_username
  admin_password      = var.vm_admin_password

  # PLANTED: password auth enabled instead of SSH key only.
  disable_password_authentication = false

  network_interface_ids = [azurerm_network_interface.app.id]

  # PLANTED: no disk_encryption_set_id (no CMK encryption).
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  # PLANTED: no boot_diagnostics block.

  tags = var.tags
}
