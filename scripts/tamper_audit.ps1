# Day 2 done check, part 2: edit one audit row directly in Postgres and
# show that GET /audit/verify names exactly that row.
#
# Default story: rewrite the $5,000 transfer's 'escalate' decision to 'allow'
# (an insider covering tracks), then verify. The original value is put back
# afterwards unless you pass -KeepBroken.
#
# Usage (repo root):  .\scripts\tamper_audit.ps1 [-Id 7] [-KeepBroken]
# -DbUser / -DbName must match the broker-postgres service in docker-compose.yml.

param(
    [int]$Id = 0,
    [switch]$KeepBroken,
    [string]$BaseUrl = "http://localhost:8000",
    [string]$DbService = "broker-postgres",
    [string]$DbUser = "agentgate",
    [string]$DbName = "agentgate"
)

$ErrorActionPreference = "Stop"

function Invoke-Sql([string]$Sql) {
    $out = docker compose exec -T $DbService psql -U $DbUser -d $DbName -v ON_ERROR_STOP=1 -tA -c $Sql
    if ($LASTEXITCODE -ne 0) { throw "psql failed: $Sql" }
    return ($out | Out-String).Trim()
}

function Get-Verify { Invoke-RestMethod -Uri "$BaseUrl/audit/verify" -UseBasicParsing }

Write-Host "`n== Tamper-evidence demo ==" -ForegroundColor Cyan

$before = Get-Verify
Write-Host ("Before: valid={0}, {1} rows checked" -f $before.valid, $before.checked)
if (-not $before.valid) { throw "Chain is already broken at row $($before.first_broken_id); fix that first." }

if ($Id -eq 0) {
    $Id = [int](Invoke-Sql "SELECT COALESCE((SELECT max(id) FROM audit_events WHERE decision = 'escalate'), (SELECT (max(id) + 1) / 2 FROM audit_events))")
}
$original = Invoke-Sql "SELECT decision || '|' || reason FROM audit_events WHERE id = $Id"
if (-not $original) { throw "No audit row with id $Id" }
$origDecision = $original.Split('|')[0]
Write-Host "Target row $Id : decision='$origDecision', reason='$($original.Substring($origDecision.Length + 1))'"

# The tamper: flip the decision. Hashes are left alone, exactly as a sloppy insider would.
$fake = if ($origDecision -eq "allow") { "deny" } else { "allow" }
Invoke-Sql "UPDATE audit_events SET decision = '$fake' WHERE id = $Id" | Out-Null
Write-Host "Tampered: row $Id decision '$origDecision' -> '$fake'" -ForegroundColor Yellow

$after = Get-Verify
Write-Host ("After:  valid={0}, first_broken_id={1}, problem: {2}" -f $after.valid, $after.first_broken_id, $after.problem)
$pass = (-not $after.valid) -and ($after.first_broken_id -eq $Id)
if ($pass) { Write-Host "[PASS] verify points at the edited row ($Id)" -ForegroundColor Green }
else       { Write-Host "[FAIL] expected verify to report row $Id" -ForegroundColor Red }

if (-not $KeepBroken) {
    Invoke-Sql "UPDATE audit_events SET decision = '$origDecision' WHERE id = $Id" | Out-Null
    $restored = Get-Verify
    Write-Host ("Restored row {0}: valid={1}" -f $Id, $restored.valid) -ForegroundColor Cyan
}

if ($pass) { exit 0 } else { exit 1 }
