#!/bin/sh
# Render entrypoint: OpenFGA (localhost only) + AgentGate broker in one container.
# Only the broker is reachable from outside; OpenFGA binds 127.0.0.1.
#
# Day 10: with FGA_DB_PASSWORD set, OpenFGA keeps its tuples in Postgres (its own role and
# schema in Supabase, see fga_db.py), so delegations written at runtime survive restarts and
# redeploys. Without it, OpenFGA runs in memory as before (delegations last until the next restart).
set -eu

PORT="${PORT:-8000}"
export PORT

if [ -n "${FGA_DB_PASSWORD:-}" ]; then
  # Creates the role + schema and prints OPENFGA_DATASTORE_URI. OpenFGA reads the URL from its
  # own env var, so it never appears in a process listing.
  # (Assign first: `eval "$(...)"` would hide a failure from set -e and boot anyway.)
  FGA_ENV="$(python /srv/deploy/fga_db.py)"
  eval "$FGA_ENV"
  export OPENFGA_DATASTORE_ENGINE=postgres
  # Supabase's free session pooler allows few connections; the broker needs its own share.
  export OPENFGA_DATASTORE_MAX_OPEN_CONNS="${OPENFGA_DATASTORE_MAX_OPEN_CONNS:-5}"
  export OPENFGA_DATASTORE_MAX_IDLE_CONNS="${OPENFGA_DATASTORE_MAX_IDLE_CONNS:-2}"
  /usr/local/bin/openfga migrate
else
  export OPENFGA_DATASTORE_ENGINE=memory
  echo "[start] FGA_DB_PASSWORD not set: OpenFGA runs in memory; delegations end at the next restart" >&2
fi

/usr/local/bin/openfga run \
  --http-addr 127.0.0.1:8080 \
  --grpc-addr 127.0.0.1:8081 \
  --playground-enabled=false \
  --metrics-enabled=false \
  --log-format json --log-level warn &

# Finds or creates the store, syncs model + seed tuples (keeps delegations), runs sanity checks,
# prints export lines.
# A failed sanity check must stop the boot, so assign first (see above).
SEED_ENV="$(python /srv/deploy/seed_fga.py)"
eval "$SEED_ENV"
export FGA_API_URL="http://127.0.0.1:8080"

cd /srv/broker
# If OpenFGA dies the broker fails closed (503) until Render restarts the service.
exec sh -c "${BROKER_CMD:-uvicorn app.main:app --host 0.0.0.0 --port $PORT}"
