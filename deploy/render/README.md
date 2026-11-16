# Deploying AgentGate to Render + Supabase (Day 3, updated Day 10)

One free Render web service runs the broker **and** OpenFGA (bound to 127.0.0.1). State that
must survive restarts (sessions, tokens, revocations, approvals, invoices, delegations, the
audit chain) lives in Supabase Postgres.

**Day 10: OpenFGA keeps its tuples in Supabase too**, under its own `openfga` role and schema,
because delegations are tuples written at runtime. At every boot `start.sh` sets up the role and
schema (`fga_db.py`), runs OpenFGA's migrations, and `seed_fga.py` *syncs* the store: it reuses the store and the model
when the policy is unchanged, replaces seed tuples that changed in `policy/tuples.yaml`, never
touches delegation tuples, and runs 15 sanity checks (the boot fails if any is wrong). Without
`FGA_DB_PASSWORD`, OpenFGA runs in memory as before and delegations end at the next restart.

Why one container: two free services would mean two cold starts in a row and an
OpenFGA endpoint on the public internet.

## 1. Supabase (database)

1. New project. Pick the region closest to your Render region. Save the DB password.
2. **Connect → Session pooler** (port **5432**, host `aws-…pooler.supabase.com`).
   Not "Direct connection" (IPv6-only; Render can't reach it) and not
   "Transaction pooler" (6543; breaks asyncpg prepared statements).
3. Build the URL and append `?sslmode=require`:
   `postgresql://postgres.<ref>:<password>@aws-<n>-<region>.pooler.supabase.com:5432/postgres?sslmode=require`
   URL-encode special characters in the password (`@` → `%40`, `#` → `%23`, `/` → `%2F`).

## 2. Render (broker + OpenFGA)

1. Commit and push (including `render.yaml`, `deploy/`, `policy/model.json`).
2. Generate **new** production secrets (don't reuse local ones):
   `docker compose run --rm broker python -m app.keys`
3. Render → **New → Blueprint** → pick the repo. It reads `render.yaml`.
   Fill the `sync: false` vars: `DATABASE_URL`, `AGENTGATE_SIGNING_KEY`,
   `AGENTGATE_ADMIN_KEY`, `AGENTGATE_ORCHESTRATOR_KEY`, `AGENTGATE_ARGS_HMAC_KEY`.
4. Deploy. In the logs you want, in order:
   `[fga_db] role openfga (created), schema openfga ready` → `[seed_fga] store=… (new) model=… (new) seed tuples=12 (+12 -0)`
   → `[seed_fga] 15 sanity checks passed` → broker startup. On later boots: `(existing)`, `(unchanged)`, `(+0 -0)`,
   and `runtime tuples kept=N` for live delegations.
5. Supabase → SQL Editor → run `deploy/supabase_rls.sql` (tables exist only after step 4).

### OpenFGA's store in Supabase (Day 10)

Add one secret in Render: `FGA_DB_PASSWORD`, a new random password of at least 16 characters
(for example `python -c "import secrets; print(secrets.token_urlsafe(32))"`). Nothing else:

- At boot, `fga_db.py` connects with `DATABASE_URL`, creates (or updates) a login role `openfga`
  with that password, a schema `openfga` it owns, and sets the role's default `search_path` to it.
  It then builds OpenFGA's URL from `DATABASE_URL` with the user swapped to `openfga.<ref>`.
- Why a role and not `?search_path=` in the URL: Supabase's pooler doesn't reliably pass a
  search_path from the connection string, so OpenFGA's tables could land in `public`, which
  Supabase serves through its REST API. A role-level default is applied by Postgres itself.
- The `openfga` role owns only its schema: it can't read or write the broker's tables.
- The password is sent to Postgres as a SCRAM-SHA-256 hash, never in plain text, so it can't
  appear in a statement log. Changing `FGA_DB_PASSWORD` and redeploying rotates it.
- OpenFGA opens at most 5 connections (`OPENFGA_DATASTORE_MAX_OPEN_CONNS`, override in Render if
  needed): the free session pooler has a small connection limit shared with the broker.
- Each OpenFGA check now reads Postgres over the network, so expect calls on Render to be slower
  than the local numbers in the README; measure with `.\scripts\run_eval.ps1 bench -Target render`
  only if you accept ~1,300 audit rows in production.
- The `openfga` schema stays out of Supabase's REST API (only `public` is exposed by default).

## 3. Point the agents at it

Create `.env.render` (gitignored!) in the repo root, ascii-encoded:

```powershell
Set-Content -Encoding ascii .env.render @(
  'AGENTGATE_URL=https://agentgate-broker.onrender.com',
  'AGENTGATE_ORCHESTRATOR_KEY=<prod orchestrator key>',
  'AGENTGATE_ADMIN_KEY=<prod admin key>'
)
Add-Content -Encoding ascii .gitignore '.env.render'
.\scripts\check_deploy.ps1
.\scripts\run_agents.ps1 -Target render pay
```

**Done check:** the `pay` run prints `transfer_funds allow audit_id=N`, the row shows in
Supabase → Table Editor → `audit_events`, and `/audit/verify` says the chain is valid.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Deploy hangs on "No open ports detected" | Broker not binding `0.0.0.0:$PORT`; set `BROKER_CMD` |
| `seed_fga … policy check failed` | `policy/model.json` stale; run `scripts/export_model_json.ps1` |
| `[fga_db] FGA_DB_PASSWORD must be at least 16 characters` | Use a longer password |
| `[fga_db] … permission denied to create role` | The `DATABASE_URL` user can't create roles; use the `postgres` user from Supabase's Connect panel |
| `password authentication failed for user "openfga…"` | Boot again: `fga_db.py` resets the role's password to `FGA_DB_PASSWORD` every boot |
| OpenFGA migrate: `too many clients` / pool errors | Lower `OPENFGA_DATASTORE_MAX_OPEN_CONNS`, or the broker's pool |
| `connection refused` / DNS error to `db.<ref>.supabase.co` | Used the direct connection; switch to session pooler |
| `prepared statement … already exists` | Used port 6543; switch to 5432 |
| `too many clients` / `max client connections reached` | Old + new instance during deploy each hold a full asyncpg pool; lower the broker's pool `max_size` to 5 |
| First request takes ~1 min | Free instance waking up; `check_deploy.ps1` warms it before demos |
