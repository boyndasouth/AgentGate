<#
Runs the demo orchestrator in Docker against the local or the Render broker.

  .\scripts\run_agents.ps1 pay                 # local broker (docker compose)
  .\scripts\run_agents.ps1 -Target render pay  # deployed broker
  .\scripts\run_agents.ps1 -Target render -Agent finance 'Pay $12 to Acme Supplies'

GOOGLE_API_KEY (+ optional AGENT_MODEL) come from .env.agents, kept apart from the broker's .env.
Orchestrator key: .env (local) or .env.render (render, which also holds AGENTGATE_URL).
Never prints the keys.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [ValidateSet('local', 'render')][string]$Target = 'local',
    [ValidateSet('researcher', 'mailer', 'finance')][string]$Agent,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)
$ErrorActionPreference = 'Stop'

function Read-EnvFile([string]$Path) {
    $vars = @{}
    if (-not (Test-Path $Path)) { throw "$Path not found" }
    foreach ($line in Get-Content $Path) {
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$') { $vars[$Matches[1]] = $Matches[2].Trim('"') }
    }
    return $vars
}

$brokerEnv = Read-EnvFile '.env'
$agentCfg = Read-EnvFile '.env.agents'
if ($Target -eq 'render') {
    $cfg = Read-EnvFile '.env.render'
    $url = $cfg['AGENTGATE_URL']
    $orch = $cfg['AGENTGATE_ORCHESTRATOR_KEY']
} else {
    $url = 'http://broker:8000'
    $orch = $brokerEnv['AGENTGATE_ORCHESTRATOR_KEY']
}
$gkey = $agentCfg['GOOGLE_API_KEY']
foreach ($pair in @(@('AGENTGATE_URL', $url), @('AGENTGATE_ORCHESTRATOR_KEY', $orch), @('GOOGLE_API_KEY', $gkey))) {
    if (-not $pair[1]) { throw "missing $($pair[0])" }
}

$cliArgs = @()
if ($Agent) { $cliArgs += @('--agent', $Agent) }
if ($Rest) { $cliArgs += $Rest }

# Pass secrets by name only (-e NAME), so they never appear in the process list.
$env:AGENTGATE_URL = $url
$env:AGENTGATE_ORCHESTRATOR_KEY = $orch
$env:GOOGLE_API_KEY = $gkey
if ($agentCfg['AGENT_MODEL']) { $env:AGENT_MODEL = $agentCfg['AGENT_MODEL'] }
$env:PYDANTIC_AI_NO_BANNER = '1'

docker compose --profile agents run --rm `
    -e AGENTGATE_URL -e AGENTGATE_ORCHESTRATOR_KEY -e GOOGLE_API_KEY -e AGENT_MODEL -e PYDANTIC_AI_NO_BANNER `
    agents @cliArgs
exit $LASTEXITCODE
