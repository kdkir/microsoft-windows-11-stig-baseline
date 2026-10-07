# Logic App: receives a request from the Function, starts a short-lived
# container that runs infra/workstation/run.sh (terraform apply or destroy),
# waits for it to finish and then deletes the container if it succeeded.

resource "azurerm_logic_app_workflow" "this" {
  name                = "logic-${local.name}"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  tags                = local.tags

  identity {
    type = "SystemAssigned"
  }
}

# Creates and deletes container groups in this resource group, and assigns
# the runner identity to them.
resource "azurerm_role_assignment" "logic_app_rg" {
  scope                = azurerm_resource_group.this.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_logic_app_workflow.this.identity[0].principal_id
}

resource "azurerm_logic_app_trigger_http_request" "this" {
  name         = "scan-request"
  logic_app_id = azurerm_logic_app_workflow.this.id
  method       = "POST"

  schema = jsonencode({
    type     = "object"
    required = ["action", "run_id", "config_url"]
    properties = {
      action      = { type = "string" }
      run_id      = { type = "string" }
      config_url  = { type = "string" }
      profile_url = { type = "string" }
      script_url  = { type = "string" }
      results_url = { type = "string" }
      status_url  = { type = "string" }
    }
  })
}

locals {
  arm_auth = {
    type     = "ManagedServiceIdentity"
    audience = "https://management.azure.com/"
  }

  container_group_uri = join("", [
    "https://management.azure.com${azurerm_resource_group.this.id}",
    "/providers/Microsoft.ContainerInstance/containerGroups/",
    "tf-@{triggerBody()?['action']}-@{triggerBody()?['run_id']}",
    "?api-version=2023-05-01",
  ])

  plain_env = {
    ACTION                     = "@{triggerBody()?['action']}"
    TF_VAR_run_id              = "@{triggerBody()?['run_id']}"
    TF_VAR_location            = azurerm_resource_group.this.location
    TF_VAR_resource_group_name = azurerm_resource_group.this.name
    TF_VAR_subnet_id           = azurerm_subnet.workstations.id
    TF_STATE_ACCOUNT           = azurerm_storage_account.this.name
    TF_STATE_CONTAINER         = azurerm_storage_container.tfstate.name
    ARM_USE_MSI                = "true"
    ARM_CLIENT_ID              = azurerm_user_assigned_identity.runner.client_id
    ARM_SUBSCRIPTION_ID        = data.azurerm_client_config.current.subscription_id
    ARM_TENANT_ID              = data.azurerm_client_config.current.tenant_id
  }

  # SAS links: passed as secure values so they don't show in the portal.
  secure_env = {
    CONFIG_URL         = "@{triggerBody()?['config_url']}"
    TF_VAR_profile_url = "@{coalesce(triggerBody()?['profile_url'], '')}"
    TF_VAR_script_url  = "@{coalesce(triggerBody()?['script_url'], '')}"
    TF_VAR_results_url = "@{coalesce(triggerBody()?['results_url'], '')}"
    TF_VAR_status_url  = "@{coalesce(triggerBody()?['status_url'], '')}"
  }

  container_group = {
    location = azurerm_resource_group.this.location
    identity = {
      type                   = "UserAssigned"
      userAssignedIdentities = { (azurerm_user_assigned_identity.runner.id) = {} }
    }
    properties = {
      osType        = "Linux"
      restartPolicy = "Never"
      containers = [{
        name = "terraform"
        properties = {
          image     = var.terraform_image
          command   = ["/bin/sh", "-c", "mkdir -p /work && wget -qO- \"$CONFIG_URL\" | tar -xz -C /work && sh /work/run.sh"]
          resources = { requests = { cpu = 1, memoryInGB = 1.5 } }
          environmentVariables = concat(
            [for k, v in local.plain_env : { name = k, value = v }],
            [for k, v in local.secure_env : { name = k, secureValue = v }],
          )
        }
      }]
    }
  }

  container_state = "body('Get_container_group')?['properties']?['instanceView']?['state']"
}

resource "azurerm_logic_app_action_custom" "create_container" {
  name         = "Create_container_group"
  logic_app_id = azurerm_logic_app_workflow.this.id

  body = jsonencode({
    type     = "Http"
    runAfter = {}
    inputs = {
      method         = "PUT"
      uri            = local.container_group_uri
      body           = local.container_group
      authentication = local.arm_auth
    }
  })
}

resource "azurerm_logic_app_action_custom" "respond" {
  name         = "Respond_accepted"
  logic_app_id = azurerm_logic_app_workflow.this.id

  body = jsonencode({
    type     = "Response"
    kind     = "Http"
    runAfter = { (azurerm_logic_app_action_custom.create_container.name) = ["Succeeded"] }
    inputs = {
      statusCode = 202
      body = {
        action          = "@{triggerBody()?['action']}"
        run_id          = "@{triggerBody()?['run_id']}"
        container_group = "tf-@{triggerBody()?['action']}-@{triggerBody()?['run_id']}"
      }
    }
  })
}

resource "azurerm_logic_app_action_custom" "wait" {
  name         = "Wait_for_container"
  logic_app_id = azurerm_logic_app_workflow.this.id

  body = jsonencode({
    type       = "Until"
    runAfter   = { (azurerm_logic_app_action_custom.respond.name) = ["Succeeded"] }
    expression = "@or(equals(${local.container_state}, 'Succeeded'), equals(${local.container_state}, 'Failed'), equals(${local.container_state}, 'Stopped'))"
    limit      = { count = 150, timeout = "PT2H30M" }
    actions = {
      Delay = {
        type     = "Wait"
        runAfter = {}
        inputs   = { interval = { count = 1, unit = "Minute" } }
      }
      Get_container_group = {
        type     = "Http"
        runAfter = { Delay = ["Succeeded"] }
        inputs = {
          method         = "GET"
          uri            = local.container_group_uri
          authentication = local.arm_auth
        }
      }
    }
  })
}

# Removes the container once Terraform succeeded. Failed containers are kept
# so their logs can be read; delete them by hand afterwards.
resource "azurerm_logic_app_action_custom" "cleanup" {
  name         = "Delete_container_if_succeeded"
  logic_app_id = azurerm_logic_app_workflow.this.id

  body = jsonencode({
    type       = "If"
    runAfter   = { (azurerm_logic_app_action_custom.wait.name) = ["Succeeded"] }
    expression = { and = [{ equals = ["@${local.container_state}", "Succeeded"] }] }
    actions = {
      Delete_container_group = {
        type     = "Http"
        runAfter = {}
        inputs = {
          method         = "DELETE"
          uri            = local.container_group_uri
          authentication = local.arm_auth
        }
      }
    }
    else = { actions = {} }
  })
}
