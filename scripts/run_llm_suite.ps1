<#
Runs the LLM-in-the-loop injection suite (eval/llm_suite.py) in the agents' Docker image:
the real agents and your model, against the local or the Render broker.

  .\scripts\run_llm_suite.ps1 -SelfTest                  # scripted models, no API key: checks the harness first
  .\scripts\run_llm_suite.ps1                            # 16 cases, 1 trial, local broker
  .\scripts\run_llm_suite.ps1 -Trials 3                  # 3 runs per case (models vary run to run)
  .\scripts\run_llm_suite.ps1 -Only W01,G01 -Model google:gemini-3.1-flash-lite
  .\scripts\run_llm_suite.ps1 -Target render             # deployed broker (posts escalations to Slack, then cancels them)

GOOGLE_API_KEY (+ optional AGENT_MODEL, GROQ_API_KEY) come from .env.agents; the orchestrator key from
.env (local) or .env.render (render). Secrets are passed by name, never on the command line.
Results: eval/results/llm-<target>-<model>-<utc>.json (the eval folder is mounted into the container).
#>
[CmdletBinding()]
param(
    [ValidateSet('local', 'render')][string]$Target = 'local',
    [int]$Trials = 1,
    [string]$Only,
    [string]$Model,
    [double]$Pause = 6,
    [switch]$SelfTest,
    [switch]$NoSave
)
$ErrorActionPreference = 'Stop'

function Read-EnvFile([string]$Path) {
    $vars = @{}
    if (-not (Test-Path $Path)) { throw "$Path not found (run from the repo root)" }
    foreach ($line in Get-Content $Path) {
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$') { $vars[$Matches[1]] = $Matches[2].Trim('"') }
    }
    return $vars
}

if ($Target -eq 'render') {
    $cfg = Read-EnvFile '.env.render'
    $url = $cfg['AGENTGATE_URL']
    $orch = $cfg['AGENTGATE_ORCHESTRATOR_KEY']
} else {
    $url = 'http://broker:8000'
    $orch = (Read-EnvFile '.env')['AGENTGATE_ORCHESTRATOR_KEY']
}
if (-not $url) { throw 'missing AGENTGATE_URL' }
if (-not $orch) { throw 'missing AGENTGATE_ORCHESTRATOR_KEY' }

$agentCfg = @{}
if (Test-Path '.env.agents') { $agentCfg = Read-EnvFile '.env.agents' }
if (-not $SelfTest -and -not $agentCfg['GOOGLE_API_KEY'] -and -not $agentCfg['GROQ_API_KEY']) {
    throw 'no model API key: set GOOGLE_API_KEY (or GROQ_API_KEY) in .env.agents, or run with -SelfTest'
}

$env:AGENTGATE_URL = $url
$env:AGENTGATE_ORCHESTRATOR_KEY = $orch
$env:GOOGLE_API_KEY = $agentCfg['GOOGLE_API_KEY']
$env:GROQ_API_KEY = $agentCfg['GROQ_API_KEY']
$env:AGENT_MODEL = $agentCfg['AGENT_MODEL']
$env:PYDANTIC_AI_NO_BANNER = '1'

$cliArgs = @('/srv/eval/llm_suite.py', '--target', $Target, '--trials', "$Trials", '--pause', "$Pause")
if ($Only) { $cliArgs += @('--only', $Only) }
if ($Model) { $cliArgs += @('--model', $Model) }
if ($SelfTest) { $cliArgs += '--self-test' }
if ($NoSave) { $cliArgs += '--no-save' }

# Rebuild first so the image has the current agents code (quick when nothing changed).
docker compose --profile agents build agents
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Running the LLM suite against $Target ..." -ForegroundColor Cyan
docker compose --profile agents run --rm `
    -v "${PWD}/eval:/srv/eval" --entrypoint python `
    -e AGENTGATE_URL -e AGENTGATE_ORCHESTRATOR_KEY -e GOOGLE_API_KEY -e GROQ_API_KEY -e AGENT_MODEL -e PYDANTIC_AI_NO_BANNER `
    agents @cliArgs
exit $LASTEXITCODE
