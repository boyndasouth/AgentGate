<#
Day 7 evals, run in a throwaway python:3.12-slim container (stdlib only, nothing to install).

  .\scripts\run_eval.ps1 suite                     # 29-case injection suite, local broker
  .\scripts\run_eval.ps1 bench                     # latency benchmark, local broker (300 rounds)
  .\scripts\run_eval.ps1 suite -Target render      # against the deployed broker (.env.render)
  .\scripts\run_eval.ps1 bench -Target render -- -n 100
  .\scripts\run_eval.ps1 suite -- --only W01,G02   # anything after -- goes to the Python script

Local: joins the compose network and calls http://broker:8000 (start the stack first:
docker compose up -d). Results land in eval\results\ on your machine.
The scripts read the keys from .env / .env.render themselves; nothing is passed on the command line.
If you have Python 3.10+ on Windows you can skip Docker: python eval\injection_suite.py
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true, Position = 0)][ValidateSet('suite', 'bench')][string]$What,
    [ValidateSet('local', 'render')][string]$Target = 'local',
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)
$ErrorActionPreference = 'Stop'

$script = @{ suite = 'eval/injection_suite.py'; bench = 'eval/latency_bench.py' }[$What]
$envFile = if ($Target -eq 'render') { '.env.render' } else { '.env' }
if (-not (Test-Path $envFile)) { throw "$envFile not found (run from the repo root)" }

$dockerArgs = @('run', '--rm', '-v', "${PWD}:/w", '-w', '/w', '-e', 'PYTHONUNBUFFERED=1')
if ($Target -eq 'local') {
    $net = docker network ls --format '{{.Name}}' | Where-Object { $_ -eq 'agentgate_default' }
    if (-not $net) { throw "compose network agentgate_default not found: run 'docker compose up -d' first" }
    $dockerArgs += @('--network', 'agentgate_default', '-e', 'AGENTGATE_URL=http://broker:8000')
}
$pyArgs = @($script, '--target', $Target) + @($Rest | Where-Object { $_ -ne '--' })

Write-Host "Running $What against $Target ..." -ForegroundColor Cyan
& docker @dockerArgs python:3.12-slim python @pyArgs
exit $LASTEXITCODE
