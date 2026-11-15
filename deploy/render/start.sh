#!/bin/sh
# Render entrypoint: OpenFGA (in-memory, localhost only) + AgentGate broker in one container.
# Only the broker is reachable from outside; OpenFGA binds 127.0.0.1.
set -eu

PORT="${PORT:-8000}"
export PORT

/usr/local/bin/openfga run \
  --datastore-engine memory \
  --http-addr 127.0.0.1:8080 \
  --grpc-addr 127.0.0.1:8081 \
  --playground-enabled=false \
  --metrics-enabled=false \
  --log-format json --log-level warn &

# Creates the store, writes model + tuples, runs sanity checks, prints export lines.
eval "$(python /srv/deploy/seed_fga.py)"
export FGA_API_URL="http://127.0.0.1:8080"

cd /srv/broker
# TODO(Day 7): supervise OpenFGA; if it dies the broker fails closed (503) until Render restarts the service.
exec sh -c "${BROKER_CMD:-uvicorn app.main:app --host 0.0.0.0 --port $PORT}"
