# Azure Function the pipeline calls. It validates the request and forwards it
# to the Logic App. Code lives in infra/function and is zip-deployed here.

data "archive_file" "function" {
  type        = "zip"
  source_dir  = "${path.module}/../function"
  output_path = "${path.module}/.build/function.zip"
}

resource "azurerm_service_plan" "function" {
  name                = "asp-${local.name}"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  os_type             = "Windows"
  sku_name            = "Y1"
  tags                = local.tags
}

resource "azurerm_windows_function_app" "this" {
  name                       = "func-${local.name}"
  resource_group_name        = azurerm_resource_group.this.name
  location                   = azurerm_resource_group.this.location
  service_plan_id            = azurerm_service_plan.function.id
  storage_account_name       = azurerm_storage_account.this.name
  storage_account_access_key = azurerm_storage_account.this.primary_access_key
  https_only                 = true
  zip_deploy_file            = data.archive_file.function.output_path
  tags                       = local.tags

  site_config {
    application_stack {
      powershell_core_version = "7.4"
    }
  }

  app_settings = {
    LOGIC_APP_TRIGGER_URL    = azurerm_logic_app_trigger_http_request.this.callback_url
    WEBSITE_RUN_FROM_PACKAGE = "1"
  }
}

data "azurerm_function_app_host_keys" "this" {
  name                = azurerm_windows_function_app.this.name
  resource_group_name = azurerm_resource_group.this.name
}
