# PROGRESS

**Current day:** Day 7 — Buffer, proof and polish ✅ DONE (2026-11-15)
**Build status:** one-week MVP complete. Every MVP feature is built, deployed and demoed; the proof numbers are in the README.
**Day 7 done check (amended):** the README shows the block rate and the latency numbers. The 90-second video was dropped by choice (Shiwin, 2026-11-15); the README has a written six-beat demo section instead.

**Repo:** github.com/boyndasouth/AgentGate (branch main) · **Broker:** https://agentgate-broker.onrender.com (OpenAPI v0.4.0; Day 7 changed decision context and deny reasons, not endpoints) · **Admin UI:** Vercel, root dir `ui/` (add the production URL here) · **DB:** Supabase, session pooler · **Slack:** two apps in one workspace, channel `C0CHR0W285R` · **Auth0:** one Regular Web App "AgentGate Admin", sign-ups disabled

## Day 7 checklist
- [x] Re-run the demo twice on the deployed version — both runs clean, all six beats, Verify intact at the end of each (2026-11-15)
- [x] Injection suite: 20 cases (`eval/cases.py`, `eval/injection_suite.py`) — **18/20 stopped (90%): 7 blocked, 11 escalated, 2 allowed (known gaps G01, G02)**; identical locally and on Render, no regressions
- [x] Latency benchmark (`eval/latency_bench.py`) — **allowed call +5.2 ms p50 / +6.5 ms p95** over an ungated request (Windows + Docker Desktop, full compose stack); OpenFGA check ≈ 2.6 ms of it
- [x] README rewritten from the plan's checklist: problem + survey numbers, Mermaid architecture diagram + request flow, policy, results, quickstart, threat model, OWASP Agentic Top 10 mapping, limitations, stack
- [~] 90-second demo video — dropped by choice; replaced by a written "Demo: six beats" section in the README
- [x] Closed gap G03 (URL egress): tainted sessions may only `read_web` allowlisted hosts (now case W13, blocked)
- [ ] Stretch: delegation chains — not started

## Tested before delivery
- Workspace stack (Postgres 16, OpenFGA v1.22.1 on Postgres, broker at HEAD): suite 20/20 matched expectations before and after G03; audit chain valid after 1,482 events; benchmark ran clean; patches checked with `git apply --check` against a fresh clone.
- G03: `fga model test` 45/45 checks (4 new read_web cases); seed_fga.py 8 sanity checks (2 new); agents offline tests 13 passed; URL tricks denied in a tainted session (`user@host`, look-alike subdomains, `example.com.evil.example`, ftp:, javascript:, junk, IPv6 literal); allowlisted host allowed with odd case, trailing dot, explicit port.
- Shiwin's machine: suite 18/20 local and on Render; `load_store.py --replace` replayed every test case against the live store; benchmark numbers above.

## Files (Day 7 patches: day7, day7-numbers, day7-g03, day7-wrapup)
- New: `eval/gate.py`, `eval/cases.py`, `eval/injection_suite.py`, `eval/latency_bench.py`, `eval/results/*.json` (Shiwin's runs), `scripts/run_eval.ps1`, `.env.example`
- Changed: `README.md`, `docker-compose.yml` (OpenFGA default tag v1.22.1), `scripts/fga.ps1` (openfga/cli:v0.7.8), `policy/model.fga` + `model.json` + `tuples.yaml` + `tests.fga.yaml`, `broker/app/{tools,decision,main}.py`, `deploy/render/seed_fga.py`, `agents/tests/test_offline.py`, `ui/src/lib/policy.ts`, `.gitignore` (`*.patch`), `PROGRESS.md` + `DECISIONS.md` (repo copies synced; were stale at Day 1)
- Removed: `day1.patch`, `agentgate-day3.patch`, `agentgate-day4.patch`

## What works
- Everything from Day 6 (local + deployed UI, Slack approvals, Realtime feed, kill switch, tamper beat).
- Evals: `.\scripts\run_eval.ps1 suite|bench [-Target render]` (Docker, python:3.12-slim, stdlib only) or `py eval\injection_suite.py`. The suite cancels its own escalations; with Slack on it still posts ~11 messages. The benchmark writes ~1,300 audit rows: run it locally, not against prod.
- Policy changes: edit `policy/`, run `.\scripts\fga.ps1 model test --tests tests.fga.yaml` (path relative to policy/), `.\scripts\export_model_json.ps1`, `py scripts/load_store.py --replace`, `docker compose up -d --build broker`; pushing redeploys Render, which reseeds OpenFGA at boot.
- Tamper beat (safe version): note the injection's `send_email` escalate row by `id` (highest id with tool_call / send_email / escalate), copy `decision` + `reason` first, edit, Verify names that id, paste back, Verify intact before moving on.

## Incident (2026-11-15, fixed)
- Prod `/audit/verify` reported row 1 modified: a past tamper beat had set row 1's `reason` (a `token_issued` row) to `policy: can_invoke ` and never restored it. Recovered the original by recomputing the hash against candidate task strings (`scopes: transfer_funds; task: Pay invoice INV-1042: $40.00 to Acme Supplies.`, matches `tokens.task` for the jti) and restored it with SQL. Chain valid again; no history lost.
- Supabase's SQL editor flags `$40` inside a string literal as an UPDATE without WHERE (its client-side parser trips on `$`); build the `$` with `chr(36)` instead.

## Open bugs / risks
- Known injection gaps: G01 (stored injection in CRM data; `query_customers` doesn't taint) and G02 (taint doesn't follow content into a new run). Fixes are written up in the README.
- URL allowlist is exact-match and static (`example.com` only, in tuples.yaml); the mock read_web doesn't follow redirects, a real one would need checks per hop.
- Approvals decided in the UI are audited as `user:shiwin via admin-api` (needs an optional `via` field in the broker's DecisionRequest + UI sends `admin-ui:auth0:<sub>`).
- UI agent grants are a static copy of tuples.yaml (`ui/src/lib/policy.ts`) — updated for G03; keep in sync on any policy change.
- Hash chain proves tampering only while the DB writer is honest; external anchoring of the head hash is future work.
- Carried: Gemini free tier flaky (scripted demo is the fallback); SvelteKit pinned to 2.70.4 (never `npm audit fix --force`); sign-out keeps the Auth0 session; kill-switch re-enable edge (wait ~1 s); asyncpg pool vs Supabase pooler; in-memory OpenFGA on Render loses runtime tuples (blocks delegation as designed); Supabase free project pauses after inactivity (unpause before showing the demo); Render cold start ~1 min (click the broker dot first).

## Next step
The plan is complete. Options, in order of value for interviews:
1. Close G01 (taint on `query_customers`, or a recipient allowlist for `send_email`) → 19/20; same pattern as G03.
2. Approver `via` field (small, finishes the audit story).
3. Delegation chains (stretch): needs runtime tuple writes → persistent OpenFGA store on Render, token exchange endpoint, new suite cases.
4. Portfolio: pin the repo, add the README's results line to your resume bullet (18/20 injection attacks stopped, +6.5 ms p95).
