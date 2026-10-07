using namespace System.Net

# HTTP entry point the pipeline calls. Validates the request and hands it to
# the Logic App, which runs Terraform to build or destroy the workstation.
#
# Body: { action: "apply" | "destroy", run_id, config_url,
#         profile_url, script_url, results_url, status_url }  (last four for apply only)
param($Request, $TriggerMetadata)

function Send-Response([HttpStatusCode] $Code, $Body) {
  Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
      StatusCode  = $Code
      ContentType = 'application/json'
      Body        = ($Body | ConvertTo-Json -Compress)
    })
}

$body = $Request.Body
$action = "$($body.action)"
$runId = "$($body.run_id)"

if ($action -notin @('apply', 'destroy')) {
  Send-Response BadRequest @{ error = "action must be 'apply' or 'destroy'" }
  return
}
# Run IDs end up in Azure resource names, so keep them short and plain.
if ($runId -cnotmatch '^[a-z0-9][a-z0-9-]{0,39}$') {
  Send-Response BadRequest @{ error = 'run_id must be 1-40 lowercase letters, digits or hyphens' }
  return
}

$required = @('config_url')
if ($action -eq 'apply') { $required += 'profile_url', 'script_url', 'results_url', 'status_url' }
foreach ($name in $required) {
  if ("$($body.$name)" -notmatch '^https://') {
    Send-Response BadRequest @{ error = "$name must be an https URL" }
    return
  }
}

$payload = [ordered]@{
  action      = $action
  run_id      = $runId
  config_url  = "$($body.config_url)"
  profile_url = "$($body.profile_url)"
  script_url  = "$($body.script_url)"
  results_url = "$($body.results_url)"
  status_url  = "$($body.status_url)"
}

try {
  Invoke-RestMethod -Method Post -Uri $env:LOGIC_APP_TRIGGER_URL `
    -ContentType 'application/json' -Body ($payload | ConvertTo-Json -Compress) | Out-Null
}
catch {
  Write-Error "Logic App call failed: $_"
  Send-Response BadGateway @{ error = 'Could not start the Logic App' }
  return
}

Write-Information "Started $action for run $runId"
Send-Response Accepted @{ action = $action; run_id = $runId; status = 'started' }
