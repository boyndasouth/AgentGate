<#
Day 11: tests for the tool registry (broker/tests/test_registry.py), run in the broker's own image.

  .\scripts\test_registry.ps1              # unit checks + live checks against the LOCAL broker
  .\scripts\test_registry.ps1 -UnitOnly    # no broker, no database needed

The live part edits the `tools` table of the local Docker Postgres directly (disables a tool,
breaks a context_map, adds test rows), checks that the gate notices on the next call, and puts
everything back. Start the stack first: docker compose up -d --build broker
It never runs against Render: it needs the database, and it must not touch production rows.
#>
[CmdletBinding()]
param([switch]$UnitOnly)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path '.env')) { throw ".env not found (run from the repo root)" }
$pyArgs = @('/srv/tests/test_registry.py')
if ($UnitOnly) { $pyArgs += '--unit-only' }

# The broker image holds the code and its requirements; the tests are mounted read-only.
# Keys and DATABASE_URL come from .env through the compose service, never the command line.
& docker compose run --rm --no-deps -v "${PWD}/broker/tests:/srv/tests:ro" `
    -e AGENTGATE_URL=http://broker:8000 -e PYTHONUNBUFFERED=1 broker python @pyArgs
exit $LASTEXITCODE
