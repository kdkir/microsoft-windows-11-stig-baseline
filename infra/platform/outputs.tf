# Values to copy into the GitHub repository (see infra/README.md).

output "github_variables" {
  description = "Repository or environment variables for the workflow."
  value = {
    AZURE_CLIENT_ID       = azurerm_user_assigned_identity.pipeline.client_id
    AZURE_TENANT_ID       = data.azurerm_client_config.current.tenant_id
    AZURE_SUBSCRIPTION_ID = data.azurerm_client_config.current.subscription_id
    AZURE_STORAGE_ACCOUNT = azurerm_storage_account.this.name
  }
}

output "azure_function_url" {
  description = "Store as the AZURE_FUNCTION_URL secret (includes the function key)."
  value       = "https://${azurerm_windows_function_app.this.default_hostname}/api/StartScan?code=${data.azurerm_function_app_host_keys.this.default_function_key}"
  sensitive   = true
}

output "resource_group" {
  value = azurerm_resource_group.this.name
}
