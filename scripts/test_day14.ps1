<#
Day 14: tests for the MCP gateway (broker/tests/test_day14.py), run in the broker's own image on
the compose network, against the mock issuer (a stand-in for Auth0) and the mock upstream.

  .\scripts\test_day14.ps1              # unit checks + the live done check against the LOCAL stack
  .\scripts\test_day14.ps1 -UnitOnly    # no broker, no database needed

The live part registers d14-bot and d14-peer (they stay registered, with no grants), imports the
mock upstream's MCP tools as mock.* (it removes them again), and drives /mcp with the real MCP
SDK client: filtered tool list, a hidden tool denied and audited, a tainting tool followed by an
egress tool that escalates and blocks until a human decides, a client that gives up.
Start the stack first: docker compose up -d --build broker mock-upstream mock-issuer
It never runs against Render (it registers agents and changes grants).
#>
[CmdletBinding()]
param([switch]$UnitOnly)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path '.env')) { throw ".env not found (run from the repo root)" }
$pyArgs = @('/srv/tests/test_day14.py')
if ($UnitOnly) { $pyArgs += '--unit-only' }

# Keys, DATABASE_URL, AUTH0_AUDIENCE and UPSTREAM_MOCK_TOKEN come from the compose service.
& docker compose run --rm --no-deps -v "${PWD}/broker/tests:/srv/tests:ro" `
    -e AGENTGATE_URL=http://broker:8000 -e MOCK_ISSUER_URL=http://mock-issuer:9191 `
    -e MOCK_UPSTREAM_URL=http://mock-upstream:9090 `
    -e PYTHONUNBUFFERED=1 broker python @pyArgs
exit $LASTEXITCODE
