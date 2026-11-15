<#
Smoke-tests the deployed broker: health (wakes it up), JWKS, audit chain.
  .\scripts\check_deploy.ps1            # URL from .env.render
#>
$ErrorActionPreference = 'Stop'
$url = (Get-Content .env.render | Where-Object { $_ -match '^AGENTGATE_URL=' }) -replace '^AGENTGATE_URL=', ''
if (-not $url) { throw 'AGENTGATE_URL missing from .env.render' }

$sw = [Diagnostics.Stopwatch]::StartNew()
$h = Invoke-RestMethod "$url/health" -TimeoutSec 120
Write-Host ("health   {0}  ({1:n1}s, includes any cold start)" -f ($h | ConvertTo-Json -Compress), $sw.Elapsed.TotalSeconds)

$jwks = Invoke-RestMethod "$url/.well-known/jwks.json"
Write-Host ("jwks     {0} key(s), alg={1}, kid={2}" -f $jwks.keys.Count, $jwks.keys[0].crv, $jwks.keys[0].kid)

$v = Invoke-RestMethod "$url/audit/verify"
Write-Host ("verify   {0}" -f ($v | ConvertTo-Json -Compress))
