<#
.SYNOPSIS
  Runs on the new Windows 11 workstation (via the Custom Script Extension, as
  SYSTEM). Installs CINC Auditor, runs the archived profile and uploads the
  JSON results plus a status file to the pipeline's SAS links.

  Always exits 0 so Terraform finishes; the pipeline reads status.json to
  decide pass or fail.
#>
param(
  [Parameter(Mandatory)] [string] $ProfileUrl,
  [Parameter(Mandatory)] [string] $ResultsUrl,
  [Parameter(Mandatory)] [string] $StatusUrl
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$work = 'C:\inspec-scan'
$profilePath = Join-Path $work 'profile.tar.gz'
$resultsPath = Join-Path $work 'results.json'
$logPath = Join-Path $work 'cinc-auditor.log'

function Send-Blob([string] $Url, [string] $Path) {
  Invoke-RestMethod -Method Put -Uri $Url -InFile $Path -UseBasicParsing `
    -ContentType 'application/json' -Headers @{ 'x-ms-blob-type' = 'BlockBlob' } | Out-Null
}

function Send-Status([hashtable] $Status) {
  $statusPath = Join-Path $work 'status.json'
  $Status['finished_at'] = (Get-Date).ToUniversalTime().ToString('o')
  $Status['computer'] = $env:COMPUTERNAME
  $Status | ConvertTo-Json | Set-Content -Path $statusPath -Encoding ASCII
  Send-Blob $StatusUrl $statusPath
}

try {
  New-Item -ItemType Directory -Force -Path $work | Out-Null

  Write-Output 'Downloading profile archive'
  Invoke-WebRequest -Uri $ProfileUrl -OutFile $profilePath -UseBasicParsing

  Write-Output 'Installing CINC Auditor'
  . { Invoke-WebRequest -Uri 'https://omnitruck.cinc.sh/install.ps1' -UseBasicParsing } | Invoke-Expression
  install -project cinc-auditor

  $cinc = Get-ChildItem -Path 'C:\cinc-project' -Recurse -Filter 'cinc-auditor.bat' -ErrorAction SilentlyContinue |
    Where-Object { $_.Directory.Name -eq 'bin' } | Select-Object -First 1 -ExpandProperty FullName
  if (-not $cinc) { throw 'CINC Auditor installed but cinc-auditor.bat was not found under C:\cinc-project.' }
  Write-Output "Using $cinc"

  Write-Output 'Running profile'
  # Native stderr must not become a terminating error here.
  $ErrorActionPreference = 'Continue'
  & $cinc exec $profilePath --reporter cli "json:$resultsPath" --enhanced-outcomes --no-color *> $logPath
  $exitCode = $LASTEXITCODE
  $ErrorActionPreference = 'Stop'
  Write-Output "CINC Auditor exit code: $exitCode"
  Get-Content $logPath -Tail 40

  $uploaded = $false
  if (Test-Path $resultsPath) {
    Send-Blob $ResultsUrl $resultsPath
    $uploaded = $true
  }
  Send-Status @{ exit_code = $exitCode; results_uploaded = $uploaded }
}
catch {
  Write-Output "Scan failed: $_"
  try { Send-Status @{ exit_code = -1; error = "$_" } } catch { Write-Output "Could not upload status: $_" }
}

exit 0
