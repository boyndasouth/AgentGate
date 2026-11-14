# PROGRESS

**Current day:** Day 1 — Policy model ✅ DONE (2026-11-14)
**Next day:** Day 2 — Broker core
**Day 2 done check:** a curl script runs all three outcomes (allow / escalate / deny), and editing one audit row makes `GET /audit/verify` report that row.

## Day 1 checklist
- [x] `policy/model.fga`: `direct_invoker` / `approval_invoker` / `approver`, `can_invoke` and `can_request_approval`; conditions `untainted` and `within_limit_untainted`
- [x] `policy/tuples.yaml`: 12 seed tuples (owners, approvers, researcher / mailer / finance grants), shared by tests and loader
- [x] `policy/tests.fga.yaml`: allow / escalate / deny for all three agents, including the $100 boundary, a tainted $40 payment, and list_objects for the mailer in clean vs tainted sessions
- [x] `scripts/fga.ps1`: runs the fga CLI from the `openfga/cli` Docker image (no Windows install)
- [x] `scripts/load_store.py`: DSL → JSON via `fga model transform`, fresh store (`--replace`), model + tuples, replays every test case against the live server, writes FGA_STORE_ID / FGA_MODEL_ID to `.env`
- [x] **Done check:** `fga model test` → Tests 4/4, Checks 39/39, ListObjects 2/2
- [x] Live store loaded: "All live checks match tests.fga.yaml"

## Day 0 items still open
- [ ] Commit and push to GitHub (scaffold + Day 1); confirm `.env` is gitignored (`git check-ignore .env`)
- [ ] Create accounts: Supabase, Auth0, Slack workspace + app, Gemini API key, Render, Vercel. **Needed by Day 3** (Gemini, Render, Supabase); Slack by Day 4; Auth0 + Vercel by Day 6
- [ ] Note each free tier's current limits in DECISIONS.md
- [ ] Confirm OPENFGA_VERSION=v1.22.1 is set in `.env`
- [ ] Pin `openfga/cli` to a version tag in `scripts/fga.ps1` (currently `:latest`)
- [~] Playground model paste: superseded by the CLI tests passing; optional

## What works
- Docker Compose stack: broker-postgres (:5433), fga-postgres, openfga v1.22.1 (:8080 API, :3000 Playground)
- `.\scripts\fga.ps1 model test --tests tests.fga.yaml` passes every case
- `py scripts\load_store.py --replace` loads a fresh `agentgate` store and verifies it live
- Current IDs in `.env`: FGA_STORE_ID=01M7DZCQJADVTQ5FZTWZDW2EG6, FGA_MODEL_ID=01M7DZCQJMYY96WR6W4K4R7Z96 (they change on every `--replace` run; the broker must read them from `.env`, never hardcode them)

## Decision mapping the broker must implement (Day 2)
1. Check `can_invoke` → true = **allow**
2. Otherwise check `can_request_approval` → true = **escalate**
3. Otherwise **deny**
- Always send both `amount` (number; 0 when not applicable) and `session_tainted` (bool) in the check context, or OpenFGA errors on conditional tuples.
- Tool → tuple coverage: read_web (researcher), read_inbox + query_customers + send_email (mailer), transfer_funds (finance). Any other agent/tool pair → deny.

## Issues hit and fixed
- Day 0: Docker Desktop disk I/O errors / corrupt postgres:17 layer → purged Docker data, re-pulled
- Day 0: PowerShell blocked downloaded scripts → Unblock-File + RemoteSigned
- Day 0: Playground bound to 127.0.0.1 inside the container → OPENFGA_PLAYGROUND_ADDR=":3000"
- Day 1: none

## Open bugs / risks
- Docker Desktop storage was flaky on Day 0; if I/O errors return, check free disk space and run chkdsk
- Accounts not created yet: Day 3's deploy depends on Render, Supabase and Gemini; create them before Day 3 starts
- Day 2 is the heaviest day (tokens, JWKS, 5 tools, decision engine, audit chain). If it runs long, use HS256 first and switch to Ed25519 on Day 3 (planned fallback)

## Next step (Day 2)
Paste the Day 2 kickoff prompt in a new chat. Build the Litestar broker: `/tokens`, `/tools/{name}`, `/.well-known/jwks.json`, Ed25519 tokens + revocation table, five mock tools, the decision engine above calling OpenFGA with context, `audit_events` with a hash chain and `GET /audit/verify`, and a curl script showing all three outcomes. Export `openapi.json` and `schema.sql` to project knowledge at the end of the day.