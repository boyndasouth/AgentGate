<#
Day 12: tests for http upstreams, upstream credentials and the agent / grant / tool admin API
(broker/tests/test_day12.py), run in the broker's own image on the compose network.

  .\scripts\test_day12.ps1              # unit checks + the live done check against the LOCAL stack
  .\scripts\test_day12.ps1 -UnitOnly    # no broker, no database needed

The live part registers `support-bot` and test tools (crm.update_ticket, d12.*), calls them
through the mock upstream, removes its tools and grants at the end. `support-bot` stays
registered. Start the stack first: docker compose up -d --build broker mock-upstream
It never runs against Render: use eval\day12_check.py for that.
#>
[CmdletBinding()]
param([switch]$UnitOnly)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path '.env')) { throw ".env not found (run from the repo root)" }
$pyArgs = @('/srv/tests/test_day12.py')
if ($UnitOnly) { $pyArgs += '--unit-only' }

# Keys, DATABASE_URL and UPSTREAM_MOCK_TOKEN come from the compose service, never the command line.
& docker compose run --rm --no-deps -v "${PWD}/broker/tests:/srv/tests:ro" `
    -e AGENTGATE_URL=http://broker:8000 -e MOCK_UPSTREAM_URL=http://mock-upstream:9090 `
    -e PYTHONUNBUFFERED=1 broker python @pyArgs
exit $LASTEXITCODE
