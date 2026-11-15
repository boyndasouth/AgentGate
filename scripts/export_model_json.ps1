<#
Regenerates policy/model.json from policy/model.fga (the Render container seeds OpenFGA from the JSON).
Run after ANY change to model.fga, then commit both files.
#>
$ErrorActionPreference = 'Stop'
$json = docker run --rm -v "${PWD}/policy:/policy:ro" openfga/cli:v0.7.8 model transform --file /policy/model.fga
if ($LASTEXITCODE -ne 0) { throw 'fga model transform failed' }
# ascii, not '>' : Windows PowerShell 5.1 redirection writes UTF-16.
$json | Set-Content -Encoding ascii policy/model.json
Write-Host 'policy/model.json updated'
