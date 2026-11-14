# Day 0 done check. Run from the repo root:  .\scripts\check-stack.ps1
$ErrorActionPreference = "Stop"

Write-Host "Containers:" -ForegroundColor Cyan
docker compose ps

Write-Host "`nOpenFGA health:" -ForegroundColor Cyan
Invoke-RestMethod http://localhost:8080/healthz | ConvertTo-Json

Write-Host "`nOpenFGA stores:" -ForegroundColor Cyan
Invoke-RestMethod http://localhost:8080/stores | ConvertTo-Json -Depth 5

Write-Host "`nPlayground:" -ForegroundColor Cyan
$r = Invoke-WebRequest http://localhost:3000/playground -UseBasicParsing
Write-Host "HTTP $($r.StatusCode)  ->  open http://localhost:3000/playground"

Write-Host "`nBroker Postgres:" -ForegroundColor Cyan
docker compose exec -T broker-postgres pg_isready -U agentgate -d agentgate

Write-Host "`nDay 0 stack is up." -ForegroundColor Green
