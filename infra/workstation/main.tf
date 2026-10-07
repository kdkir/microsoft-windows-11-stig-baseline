# One throwaway Windows 11 workstation per pipeline run. Applied and destroyed
# by run.sh inside a short-lived container started by the Logic App.

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
  # Settings are passed with -backend-config by run.sh (one state file per run).
  backend "azurerm" {}
}

provider "azurerm" {
  features {}
  # Authenticates with the container's managed identity (ARM_USE_MSI etc.).
  resource_provider_registrations = "none"
}

locals {
  name = "inspec-${var.run_id}"
  tags = {
    purpose = "inspec-windows11-scan"
    run_id  = var.run_id
  }
}

resource "random_password" "admin" {
  length      = 24
  special     = true
  min_upper   = 2
  min_lower   = 2
  min_numeric = 2
  min_special = 2
}

resource "azurerm_network_interface" "this" {
  name                = "nic-${local.name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = local.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_windows_virtual_machine" "this" {
  name                  = "vm-${local.name}"
  computer_name         = "inspec-ws"
  location              = var.location
  resource_group_name   = var.resource_group_name
  size                  = var.vm_size
  admin_username        = "inspecadmin"
  admin_password        = random_password.admin.result
  network_interface_ids = [azurerm_network_interface.this.id]
  license_type          = var.license_type
  secure_boot_enabled   = true
  vtpm_enabled          = true
  tags                  = local.tags

  os_disk {
    name                 = "osdisk-${local.name}"
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsDesktop"
    offer     = "windows-11"
    sku       = var.image_sku
    version   = "latest"
  }
}

# Installs CINC Auditor and runs the profile. Terraform waits for the script to
# finish, so `apply` returns once results have been uploaded.
resource "azurerm_virtual_machine_extension" "scan" {
  name                       = "inspec-scan"
  virtual_machine_id         = azurerm_windows_virtual_machine.this.id
  publisher                  = "Microsoft.Compute"
  type                       = "CustomScriptExtension"
  type_handler_version       = "1.10"
  auto_upgrade_minor_version = true
  tags                       = local.tags

  protected_settings = jsonencode({
    fileUris = [var.script_url]
    commandToExecute = join(" ", [
      "powershell.exe -NoProfile -ExecutionPolicy Bypass -File run-scan.ps1",
      "-ProfileUrl \"${var.profile_url}\"",
      "-ResultsUrl \"${var.results_url}\"",
      "-StatusUrl \"${var.status_url}\"",
    ])
  })

  timeouts {
    create = "90m"
  }
}
