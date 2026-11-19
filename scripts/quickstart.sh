#!/usr/bin/env bash
# One command to a working local AgentGate stack on Linux, macOS, WSL or GitHub Codespaces.
# (Windows PowerShell users: the Quickstart in the README does the same steps.)
#
#   bash scripts/quickstart.sh
#
# Needs Docker with the compose plugin and Python 3.10+. It does not need Slack, Auth0 or a model key:
# approvals go through the admin API and the identity provider is the local mock issuer.
# Safe to run again: it keeps your .env and the secrets already in it.
set -euo pipefail
cd "$(dirname "$0")/.."

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

[ -f .env ] || cp .env.example .env
# .env.example ends without a secret block; make sure appends start on a new line.
[ -z "$(tail -c1 .env)" ] || echo >> .env

say "1/5 OpenFGA and the databases"
docker compose up -d openfga broker-postgres

say "2/5 Broker secrets (kept if .env already has them)"
if ! grep -q '^AGENTGATE_SIGNING_KEY=' .env; then
  # -T: no terminal, so the output has no carriage returns
  docker compose run --rm --no-deps -T broker python -m app.keys >> .env
else
  echo "already in .env"
fi

say "3/5 Policy model and seed tuples"
python3 -m pip install --quiet pyyaml 2>/dev/null || python3 -m pip install --quiet --break-system-packages pyyaml
python3 scripts/load_store.py --replace

say "4/5 Broker"
docker compose up -d --build broker
for i in $(seq 1 60); do
  if curl -fsS http://localhost:8000/health >/dev/null 2>&1; then break; fi
  [ "$i" -lt 60 ] || { echo "the broker did not come up; see: docker compose logs broker" >&2; exit 1; }
  sleep 2
done
curl -fsS http://localhost:8000/health; echo

say "5/5 Ready"
cat <<'MSG'
Watch the demo (an injected agent tries to email the customer list):
    python3 eval/export_tour.py --show --out -

Run the 36-case injection suite:
    python3 eval/injection_suite.py

Measure the gate's latency:
    python3 eval/latency_bench.py

The broker's API docs are at http://localhost:8000/schema
MSG
