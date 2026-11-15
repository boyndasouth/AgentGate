# Deploying AgentGate to Render + Supabase (Day 3)

One free Render web service runs the broker **and** OpenFGA (in-memory, bound to
127.0.0.1). At every boot `seed_fga.py` creates the store from `policy/model.json` +
`policy/tuples.yaml`, runs 6 policy sanity checks (boot fails if any is wrong), and
exports `FGA_STORE_ID` / `FGA_MODEL_ID` to the broker. State that must survive restarts
(sessions, tokens, revocations, approvals, audit chain) lives in Supabase Postgres.

Why one container: two free services would mean two cold starts in a row and an
OpenFGA endpoint on the public internet. Policy tuples are static seed data, so losing
them on restart costs nothing; they are re-seeded in about a second.

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
   `[seed_fga] store=… tuples=12` → `[seed_fga] 6 sanity checks passed` → broker startup.
5. Supabase → SQL Editor → run `deploy/supabase_rls.sql` (tables exist only after step 4).

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
| `connection refused` / DNS error to `db.<ref>.supabase.co` | Used the direct connection; switch to session pooler |
| `prepared statement … already exists` | Used port 6543; switch to 5432 |
| `too many clients` / `max client connections reached` | Old + new instance during deploy each hold a full asyncpg pool; lower the broker's pool `max_size` to 5 |
| First request takes ~1 min | Free instance waking up; `check_deploy.ps1` warms it before demos |
