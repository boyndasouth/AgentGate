<#
Day 13: tests for agents logging in as themselves (broker/tests/test_day13.py), run in the
broker's own image on the compose network, against the mock issuer (a stand-in for Auth0).

  .\scripts\test_day13.ps1              # unit checks + the live done check against the LOCAL stack
  .\scripts\test_day13.ps1 -UnitOnly    # no broker, no database needed

The live part registers d13-bot, d13-peer and d13-other (they stay registered, with no grants),
logs in with tokens from the mock issuer and runs examples\agent_login.py as a standalone agent.
Start the stack first: docker compose up -d --build broker mock-upstream mock-issuer
It never runs against Render: there, run examples\agent_login.py with a real Auth0 client.
#>
[CmdletBinding()]
param([switch]$UnitOnly)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path '.env')) { throw ".env not found (run from the repo root)" }
$pyArgs = @('/srv/tests/test_day13.py')
if ($UnitOnly) { $pyArgs += '--unit-only' }

# Keys, DATABASE_URL and AUTH0_AUDIENCE come from the compose service, never the command line.
& docker compose run --rm --no-deps -v "${PWD}/broker/tests:/srv/tests:ro" `
    -v "${PWD}/examples:/srv/examples:ro" `
    -e AGENTGATE_URL=http://broker:8000 -e MOCK_ISSUER_URL=http://mock-issuer:9191 `
    -e PYTHONUNBUFFERED=1 broker python @pyArgs
exit $LASTEXITCODE
