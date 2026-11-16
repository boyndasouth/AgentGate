# PROGRESS

**Current day:** Day 9 — G04 closed + LLM-in-the-loop mode (2026-11-16): `day9.patch` applied and checked on Shiwin's machine, LLM numbers in the README (`day9-readme.patch`). **Not yet pushed.**
**Build status:** one-week MVP complete (Day 7). Day 8 (applied, pushed, Render suite 20/21) closed G01/G02, added the approver `via` field and audit anchoring. Day 9 closes G04 with a payee allowlist, adds known gap G05, and adds the LLM-in-the-loop suite. Still to do: delegation chains (stretch).
**Headline numbers after Day 9:** **21/22 attacks stopped (95%)** worst case (local, Shiwin's machine); with Gemini 3.1 Flash-Lite the model tried the attack in **14/35 runs (40%)** and **3/35 (9%)** got through the gate, all G05; latency +5.2 ms p50 / +6.5 ms p95 (re-measured by Shiwin after Day 8: +5.17 / +6.55, unchanged).

**Repo:** github.com/boyndasouth/AgentGate (branch main) · **Broker:** https://agentgate-broker.onrender.com (deployed: OpenAPI v0.5.0 since Day 8; Day 9 patch is v0.6.0: payee in the decision context, no endpoint changes) · **Admin UI:** Vercel, root dir `ui/` (add the production URL here) · **DB:** Supabase, session pooler · **Slack:** two apps in one workspace, channel `C0CHR0W285R` · **Auth0:** one Regular Web App "AgentGate Admin", sign-ups disabled

## Day 9 checklist
- [x] **G04 closed (payee allowlist).** `transfer_funds` direct grant is now `within_limit_known_payee` (amount ≤ 100 AND clean session AND `to_account` in `[acct_acme_supplies]`, exact match). Replaces `within_limit_untainted`. Escalation reason says "payee is not on the allowlist" without the account number.
- [x] **New known gap G05** (duplicate-invoice fraud: $90 to the known payee in a new run → allowed). Suite: 22 cases, **21/22 stopped (7 blocked, 14 escalated, 1 allowed)** in the workspace.
- [x] **Control characters in policy context.** OpenFGA rejects a check whose context holds a control character, so `to_account: "x\n"` or a URL host with `\x07` gave a 503 "policy engine unavailable" (still a deny, but a wrong reason). `policy_safe()` in tools.py turns such values into '' (never on an allowlist). The host case existed since Day 7.
- [x] Callers moved to the allowlisted payee: UI demo (already `acct_acme_supplies`), `demo_day2.ps1` (`vendor-1042` → `acct_acme_supplies`), latency bench (`ACCT-BENCH` → `acct_acme_supplies`), orchestrator `pay` task (now names the account), offline FakeGate, UI mock broker.
- [x] **LLM-in-the-loop suite** (`eval/llm_cases.py`, `eval/llm_suite.py`, `scripts/run_llm_suite.ps1`): 16 of 22 cases run through the real agents; 6 are n/a (the agents' tools can't express them, or the orchestrator fixes the scopes). Reports "model tried it" vs. "got through". `-SelfTest` checks the harness with scripted models, no API key.
- [x] Shiwin: applied `day9.patch`; 63/63 + 5/5, suite 21/22 (G05), `demo_day2.ps1` all pass, LLM self-test passed in Docker (2026-11-16)
- [x] LLM run, Gemini 3.1 Flash-Lite, 3 trials: 48 runs, 13 provider errors (503/429), 35 valid; model tried the attack 14/35, through the gate 3/35 (all G05). Numbers in the README.
- [ ] Push Day 9, run `.\scripts\run_eval.ps1 suite -Target render`, commit `eval/results/*.json`
- [ ] Optional: a second LLM batch when Gemini is less busy (several rows have 1 valid run); merge the result files
- [x] Day 8 leftover: the anchor workflow ran successfully; `audit-anchors` branch live, first anchor at row 291 (2026-11-16)
- [ ] Stretch: delegation chains — not started

## Day 9: apply and run
1. `git pull`, then `git apply --check day9.patch` and `git apply day9.patch`.
2. Local: `.\scripts\fga.ps1 model test --tests tests.fga.yaml` (63 checks, 5 list_objects), `py scripts/load_store.py --replace`, `docker compose up -d --build broker`, `.\scripts\run_eval.ps1 suite` (expect 21/22, known gap G05), `.\scripts\demo_day2.ps1`.
3. `.\scripts\run_llm_suite.ps1 -SelfTest` (no API key; expect "self-test: all passed"), then `.\scripts\run_llm_suite.ps1 -Trials 3` (about 300 model requests: one model's free daily quota may not cover it; use `-Trials 1` or a fallback list in AGENT_MODEL).
4. Commit and push; `.\scripts\run_eval.ps1 suite -Target render`; commit `eval/results/*.json`.

## Day 9: tested before delivery (workspace: Postgres 16, OpenFGA v1.22.1 in memory, broker at the patch, fresh database)
- `fga model test` 63/63 checks, 5/5 list_objects; `load_store.py --replace` replayed every case; `seed_fga.py` 13 sanity checks (2 new); `model.json` byte-identical to a fresh transform.
- Suite 21/22, no regressions, chain valid. Payee edge cases against the live broker, 11 cases: known payee allowed at $40 and $100; unknown payee, upper case, leading space, trailing newline, empty → escalate with "payee is not on the allowlist" and no account number in the reason; $5,000 known payee → "amount 5000" only; tainted → escalate. Control characters in a URL host → normal deny, not 503. Day 8 recipient and `via` tests still pass; anchoring publish + check pass.
- LLM suite: `--self-test` all passed (obedient scripted models reproduce the worst-case outcome on all 16 cases; careful ones never count as attempts; the case page reaches the next agent's prompt). Also checked: a missing payload is caught as an error, inbox and CRM content reach the model, no approval left pending, report and JSON with mixed outcomes, and the container layout (agents at /srv/agents, eval mounted at /srv/eval, keys from env only).
- Agents offline tests 14 passed; UI smoke all passed, `svelte-check` 0 errors, `vite build` ok; short latency run in line with Day 8.
- **Not tested:** real Gemini runs (no model keys in the workspace), `run_llm_suite.ps1` and `demo_day2.ps1` (no PowerShell or Docker daemon here), Render.

## Day 8 checklist
- [x] **G01 closed (recipient allowlist).** `send_email` direct grant is now `untainted_allowed_recipient` (clean session AND recipient domain in `[agentgate.example]`); any other send escalates. This also closed G02 (cross-session, by email). Suite: G01 and G02 now expect `escalate`.
- [x] **New known gap G04** added so the score stays honest: text carried into a new run, then a $49 payment to a new payee → allowed. Suite is now 21 cases: **20/21 stopped (7 blocked, 13 escalated, 1 allowed)** in the workspace. Fix (not built): payee allowlist on `transfer_funds`.
- [x] **Approver `via` field.** `DecisionRequest` takes optional `via` (`admin-ui:<Auth0 sub>` only); the UI sends it from the server-side session; audit reads `user:shiwin via admin-ui:auth0|…`. Without it: `admin-api`, so `decide.ps1` still works.
- [x] **Audit chain anchored outside the database.** `GET /audit/checkpoint` (signed head), `GET /audit/hashes?ids=`, `scripts/anchor.py publish|check`, `.github/workflows/anchor.yml` (every 6 h → `audit-anchors` branch). A full rewrite of the chain, a truncated tail and a forged anchors file are all caught.
- [ ] LLM-in-the-loop suite mode — not started (needs case-specific content in the mock tools and real Gemini runs on Shiwin's machine)
- [ ] Delegation chains — not started (needs a persistent OpenFGA store on Render)
- [x] Shiwin: applied, local checks passed (55/55, suite 20/21, demo all PASS), pushed, Render suite 20/21 and latency re-run committed (2026-11-16)
- [x] Anchor workflow: first run succeeded, `audit-anchors` branch created (2026-11-16)

## Day 8: apply and deploy
1. `git apply --check day8.patch`, then `git apply day8.patch`.
2. Local: `.\scripts\fga.ps1 model test --tests tests.fga.yaml` (55 checks, 3 list_objects), `py scripts/load_store.py --replace`, `docker compose up -d --build broker`, `.\scripts\run_eval.ps1 suite` (expect 20/21, no regressions), `.\scripts\demo_inject.ps1 -AutoDeny`.
3. Commit and push. Render rebuilds the broker and reseeds OpenFGA (11 sanity checks at boot); Vercel rebuilds the UI. **Wait for Render to be live before approving anything from the UI**: the new UI sends `via`, which the old broker rejects ("Validation failed").
4. GitHub → Actions → "Anchor audit chain" → Run workflow (first run creates the `audit-anchors` branch). Then `py scripts/anchor.py check --url https://agentgate-broker.onrender.com --file https://raw.githubusercontent.com/boyndasouth/AgentGate/audit-anchors/anchors.jsonl`.
5. `.\scripts\run_eval.ps1 suite -Target render` and `bench`; commit `eval/results/*.json`; put the Render numbers in the README if they differ.

## Day 8: tested before delivery (workspace: Postgres 16, OpenFGA v1.22.1 in memory, broker at the patch)
- `fga model test` 55/55 checks, 3/3 list_objects; `load_store.py --replace` replayed every case live; `seed_fga.py` 11 sanity checks (3 new); `model.json` regenerated with fga CLI v0.7.8 and byte-identical to a fresh transform.
- Suite 20/21, no regressions, audit chain valid after the run.
- Recipient parsing against the live broker, 19 cases: internal address allowed (also in mixed case); surrounding spaces, outside domain, subdomain, look-alike suffix, trailing dot, two addresses, display name, two `@`, newline + bcc, Cyrillic look-alike, no `@`, empty, trailing newline → all escalate; tainted + internal → escalate. The address is judged exactly as sent (no trimming).
- `via`: 7 malformed or forged labels → 400 and the approval stays pending; valid label lands in `approvals.approver`, `resolved_via` and the audit row; a non-approver's refusal is audited with the label; no `via` → `admin-api`.
- Anchoring: single-row edit (caught by verify), full rewrite from a row before, between and after the anchors (caught, except after the latest anchor, which is the documented window), truncated tail (caught), anchors file edited to match a rewrite (caught by the signature; not caught without `cryptography`, so the workflow uses `--require-signature`), checkpoint JWS used as a bearer token (401). Workflow shell steps run three times against a local bare repo: branch created, no-op run, append run.
- Agents offline tests 14 passed (1 new); UI smoke 22 checks (4 new), `svelte-check` 0 errors, `vite build` ok.
- **Not tested:** the GitHub Action on GitHub itself, Vercel's handling of the `audit-anchors` branch, Render/Supabase, Slack, `demo_inject.ps1` (no PowerShell in the workspace), latency on Shiwin's machine.

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
- Known injection gap: G05 (small payment to the known payee in a clean run). Fixes: invoice matching, per-payee daily budget, or carry taint across runs.
- Every email to an outside address and every payment to a new account needs approval, including legitimate ones (the cost of closing G01 and G04). Both allowlists are static, one entry each, in tuples.yaml.
- URL allowlist is exact-match and static (`example.com` only, in tuples.yaml); the mock read_web doesn't follow redirects, a real one would need checks per hop.
- Anchoring window: rows after the latest anchor (up to 6 h) can be rewritten unnoticed until the next one. GitHub pauses scheduled workflows after 60 days without repo activity; re-enable it in the Actions tab if that happens.
- `audit-anchors` branch: it carries `ui/vercel.json` with `git.deploymentEnabled: false` so Vercel should skip it. Untested; if Vercel still builds (and fails) previews for it, set an Ignored Build Step in the Vercel project.
- UI agent grants are a static copy of tuples.yaml (`ui/src/lib/policy.ts`) — updated for G01; keep in sync on any policy change.
- Carried: Gemini free tier flaky (scripted demo is the fallback); SvelteKit pinned to 2.70.4 (never `npm audit fix --force`); sign-out keeps the Auth0 session; kill-switch re-enable edge (wait ~1 s); asyncpg pool vs Supabase pooler; in-memory OpenFGA on Render loses runtime tuples (blocks delegation as designed); Supabase free project pauses after inactivity (the 6-hourly anchor job now queries it, which should keep it awake; unpause before a demo if not); Render cold start ~1 min (click the broker dot first).

## Next step
Push Day 9 and run the Render suite. Then:
1. Portfolio: resume bullets (21/22 attacks stopped worst case, the LLM numbers, +6.5 ms p95, anchored audit log), interview prep, README screenshot.
2. Delegation chains (stretch, 2 to 3 days): persistent OpenFGA store on Render, token-exchange endpoint, new suite cases.
3. Close G05 if wanted: per-payee daily budget (needs a running total, so state outside OpenFGA) or taint carried across runs.
