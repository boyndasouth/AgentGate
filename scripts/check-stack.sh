#!/usr/bin/env bash
# Day 0 done check (Git Bash / WSL / CI). PowerShell users: scripts/check-stack.ps1
set -euo pipefail
docker compose ps
echo "--- OpenFGA health";  curl -fsS http://localhost:8080/healthz; echo
echo "--- OpenFGA stores";  curl -fsS http://localhost:8080/stores; echo
echo "--- Playground";      curl -fsS -o /dev/null -w "HTTP %{http_code}\n" http://localhost:3000/playground
echo "--- Broker Postgres"; docker compose exec -T broker-postgres pg_isready -U agentgate -d agentgate
echo "Day 0 stack is up."
