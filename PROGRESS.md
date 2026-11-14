# PROGRESS

**Current day:** Day 0 — Setup
**Today's done check:** OpenFGA playground loads at http://localhost:3000/playground

## Day 0 checklist
- [x] Repo scaffold: `broker/`, `agents/`, `ui/`, `policy/`, `db/init/`, `scripts/`, `docker-compose.yml`, `.env.example`, `.gitignore`
- [x] `docker-compose.yml`: OpenFGA + its own Postgres (with migrate step), separate broker Postgres on host port 5433
- [x] `policy/model.fga` copied from the plan (validated with OpenFGA's DSL parser)
- [ ] Run `docker compose up -d` on the Windows machine and pass `scripts/check-stack.ps1`
- [ ] Open the Playground, paste `policy/model.fga`, confirm it renders
- [ ] Push the scaffold to GitHub
- [ ] Create accounts: Supabase, Auth0, Slack workspace + app, Gemini API key, Render, Vercel
- [ ] Note each free tier's current limits in DECISIONS.md

## What works
- Compose file passes `docker compose config`; model.fga parses (types: user, agent, tool; conditions: within_limit, untainted)
- Not yet run end to end on the real machine

## Open bugs / risks
- None yet

## Next step (Day 1)
Write `policy/tests.fga.yaml` (allow / escalate / deny for researcher, mailer, finance) and `policy/load_store.py`; pass `fga model test`.
