<#
Lists pending approvals, or approves / denies one, through the admin API.
Fallback for when Slack is off or broken; same rules as a Slack click
(OpenFGA `approver` check, audited, one decision per approval).

  .\scripts\decide.ps1                                  # list pending (local broker)
  .\scripts\decide.ps1 -Status all                      # list recent, any status
  .\scripts\decide.ps1 -Id <approval-uuid> -Deny        # deny as shiwin
  .\scripts\decide.ps1 -Id <approval-uuid> -Approve
  .\scripts\decide.ps1 -Target render -Id <uuid> -Deny  # deployed broker (.env.render)
#>
[CmdletBinding()]
param(
    [ValidateSet('local', 'render')][string]$Target = 'local',
    [string]$Id,
    [switch]$Approve,
    [switch]$Deny,
    [string]$Approver = 'shiwin',
    [ValidateSet('pending', 'approved', 'denied', 'expired', 'all')][string]$Status = 'pending'
)
$ErrorActionPreference = 'Stop'

function Read-EnvValue([string]$Path, [string]$Name) {
    if (-not (Test-Path $Path)) { throw "$Path not found" }
    $line = Get-Content $Path | Where-Object { $_ -match "^\s*$Name\s*=" } | Select-Object -First 1
    if (-not $line) { throw "$Name missing from $Path" }
    return ($line -replace "^\s*$Name\s*=\s*", '').Trim().Trim('"')
}

if ($Target -eq 'render') {
    $url = Read-EnvValue '.env.render' 'AGENTGATE_URL'
    $key = Read-EnvValue '.env.render' 'AGENTGATE_ADMIN_KEY'
} else {
    $url = 'http://localhost:8000'
    $key = Read-EnvValue '.env' 'AGENTGATE_ADMIN_KEY'
}
$headers = @{ 'X-Admin-Key' = $key }

if (-not $Id) {
    $rows = Invoke-RestMethod "$url/approvals?status=$Status" -Headers $headers -TimeoutSec 120
    if (-not $rows) { Write-Host "no $Status approvals"; exit 0 }
    foreach ($r in $rows) {
        $argText = ($r.summary.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', '
        Write-Host ("{0}  {1,-8} {2}->{3}  {4}  [{5}]  expires {6}" -f $r.id, $r.status, $r.agent_id, $r.tool, $r.reason, $argText, $r.expires_at)
    }
    exit 0
}

if ($Approve -eq $Deny) { throw 'pass exactly one of -Approve or -Deny' }
$body = @{ approve = [bool]$Approve; approver = $Approver } | ConvertTo-Json -Compress
try {
    $r = Invoke-RestMethod "$url/approvals/$Id/decision" -Method Post -Headers $headers `
        -ContentType 'application/json' -Body $body -TimeoutSec 120
    Write-Host ("{0}: {1} by {2}" -f $r.id, $r.status, $r.approver)
} catch {
    # Windows PowerShell 5.1 throws on 4xx; show the broker's reason.
    $msg = $_.ErrorDetails.Message
    if (-not $msg) { $msg = $_.Exception.Message }
    Write-Host "not applied: $msg"
    exit 1
}
