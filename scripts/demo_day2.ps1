# Day 2 done check, part 1: allow, escalate and deny through the AgentGate broker.
# Usage (repo root):  .\scripts\demo_day2.ps1
# Works in Windows PowerShell 5.1 and PowerShell 7. Reads keys from .env.

param([string]$BaseUrl = "http://localhost:8000")

$ErrorActionPreference = "Stop"

# --- read .env -------------------------------------------------------------
$envFile = Join-Path $PSScriptRoot "..\.env"
$cfg = @{}
foreach ($line in Get-Content $envFile) {
    if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$') { $cfg[$Matches[1]] = $Matches[2].Trim('"') }
}
foreach ($k in "AGENTGATE_ADMIN_KEY", "AGENTGATE_ORCHESTRATOR_KEY") {
    if (-not $cfg[$k]) { throw "$k missing from .env (run: docker compose run --rm broker python -m app.keys)" }
}
$orch  = @{ "X-Orchestrator-Key" = $cfg["AGENTGATE_ORCHESTRATOR_KEY"] }
$admin = @{ "X-Admin-Key" = $cfg["AGENTGATE_ADMIN_KEY"] }

# --- HTTP helper that returns status + body for 2xx and 4xx alike ----------
function Invoke-Gate {
    param([string]$Method, [string]$Path, $Body = $null, [hashtable]$Headers = @{})
    $p = @{ Method = $Method; Uri = "$BaseUrl$Path"; Headers = $Headers; UseBasicParsing = $true }
    if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10 -Compress); $p.ContentType = "application/json" }
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $r = Invoke-WebRequest @p -SkipHttpErrorCheck
        return [pscustomobject]@{ Status = [int]$r.StatusCode; Body = ($r.Content | ConvertFrom-Json) }
    }
    try {
        $r = Invoke-WebRequest @p
        return [pscustomobject]@{ Status = [int]$r.StatusCode; Body = ($r.Content | ConvertFrom-Json) }
    } catch {
        if (-not $_.Exception.Response) { throw }
        return [pscustomobject]@{ Status = [int]$_.Exception.Response.StatusCode; Body = ($_.ErrorDetails.Message | ConvertFrom-Json) }
    }
}

$script:failures = 0
function Show-Step {
    param([string]$Title, $Resp, [int]$Expect)
    $ok = $Resp.Status -eq $Expect
    if (-not $ok) { $script:failures++ }
    $tag = if ($ok) { "PASS" } else { "FAIL" }
    $color = if ($ok) { "Green" } else { "Red" }
    $decision = if ($Resp.Body.decision) { $Resp.Body.decision.ToUpper() } elseif ($Resp.Body.error) { $Resp.Body.error } else { "" }
    Write-Host ("[{0}] {1}" -f $tag, $Title) -ForegroundColor $color
    Write-Host ("       HTTP {0} (expected {1})  {2}  {3}" -f $Resp.Status, $Expect, $decision, $Resp.Body.reason)
}

function New-AgentToken {
    param([string]$Agent, [string[]]$Scopes, [string]$Task, [string]$SessionId = $null)
    $body = @{ agent_id = $Agent; task = $Task; scopes = $Scopes }
    if ($SessionId) { $body.session_id = $SessionId }
    return Invoke-Gate POST "/tokens" $body $orch
}

function Invoke-Tool {
    param([string]$Token, [string]$Tool, [hashtable]$ToolArgs)
    return Invoke-Gate POST "/tools/$Tool" @{ args = $ToolArgs } @{ Authorization = "Bearer $Token" }
}

# --- 0. broker up -----------------------------------------------------------
Write-Host "`n== AgentGate Day 2 demo ==" -ForegroundColor Cyan
$h = Invoke-Gate GET "/health"
Show-Step "Broker healthy and OpenFGA reachable (openfga=$($h.Body.openfga))" $h 200

# --- 1. finance gets a 10-minute token scoped to transfer_funds -------------
$t = New-AgentToken -Agent "finance" -Scopes @("transfer_funds") -Task "Pay vendor invoices"
Show-Step "Finance token issued (expires_in=$($t.Body.expires_in)s, session $($t.Body.session_id))" $t 201
$fin = $t.Body.access_token
$session = $t.Body.session_id

# --- 2. ALLOW: $40 invoice (Day 10: it must be an open invoice in accounts payable) ---
$inv = Invoke-Gate POST "/invoices" @{ payee = "acct_acme_supplies"; amount = 40 } $admin
Show-Step "Accounts payable has open invoice $($inv.Body.id) for `$40" $inv 201
$r = Invoke-Tool $fin "transfer_funds" @{ amount = 40; to_account = "acct_acme_supplies"; memo = "Invoice $($inv.Body.id)"; invoice_id = $inv.Body.id }
Show-Step "ALLOW    finance pays a `$40 invoice" $r 200
if ($r.Body.result) { Write-Host "       result: $($r.Body.result | ConvertTo-Json -Compress)" }

# --- 3. ESCALATE: $5,000 -----------------------------------------------------
$r = Invoke-Tool $fin "transfer_funds" @{ amount = 5000; to_account = "unknown-77"; memo = "Urgent wire" }
Show-Step "ESCALATE finance tries `$5,000 (approval $($r.Body.approval_id), status $($r.Body.status))" $r 202

# --- 4. DENY at issuance: researcher asks for money scope -------------------
$r = New-AgentToken -Agent "researcher" -Scopes @("transfer_funds") -Task "Buy a report" -SessionId $session
Show-Step "DENY     researcher cannot even get a transfer_funds token" $r 403

# --- 5. DENY at the gate: researcher calls a tool outside its token scope ---
$t = New-AgentToken -Agent "researcher" -Scopes @("read_web") -Task "Research competitor pricing" -SessionId $session
Show-Step "Researcher token issued (scope read_web)" $t 201
$res = $t.Body.access_token
$r = Invoke-Tool $res "read_web" @{ url = "https://example.com/pricing" }
Show-Step "ALLOW    researcher reads a web page" $r 200
$r = Invoke-Tool $res "transfer_funds" @{ amount = 1; to_account = "attacker" }
Show-Step "DENY     researcher calls transfer_funds with a read_web token" $r 403

# --- 6. Kill switch ----------------------------------------------------------
$r = Invoke-Gate POST "/agents/finance/disable" @{ reason = "demo kill switch" } $admin
Show-Step "Kill switch: finance disabled" $r 200
$r = Invoke-Tool $fin "transfer_funds" @{ amount = 40; to_account = "acct_acme_supplies" }
Show-Step "DENY     finance's existing token is dead right away" $r 401
$r = Invoke-Gate POST "/agents/finance/enable" $null $admin
Show-Step "Finance re-enabled (old tokens stay revoked)" $r 200

# --- 7. Audit chain ----------------------------------------------------------
$r = Invoke-Gate GET "/audit/verify"
Show-Step "Audit chain valid=$($r.Body.valid), $($r.Body.checked) rows checked" $r 200
if (-not $r.Body.valid) { $script:failures++; Write-Host "       first broken row: $($r.Body.first_broken_id)  $($r.Body.problem)" -ForegroundColor Red }

Write-Host ""
if ($script:failures -eq 0) { Write-Host "All steps passed." -ForegroundColor Green; exit 0 }
Write-Host "$($script:failures) step(s) failed." -ForegroundColor Red; exit 1
