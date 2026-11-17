# PROGRESS

**Current day:** Day 12: forwarding to HTTP upstreams, credentials, agent and grant API (2026-11-16). `day12.patch` (against main at 4d0dd58) applied and pushed; the Render redeploy check passed. `day12-followup.patch` delivered. Day 11 is done and deployed. Second day of the Day 11+ phase (open the broker to any agent, see `DAY11_PLAN.md` in the project docs).
**Build status:** Days 0-12 are done and deployed. Day 12 makes agents, grants, approvers and tools API data (no seed file needed), and adds `http` upstreams: an allowed call goes to a real API with a credential only the broker holds.
**Headline numbers after Day 12 (workspace):** **33/33 attacks stopped** (14 blocked, 19 escalated, 0 allowed): the 29 from Day 11 unchanged plus R01-R04. Day 12 tests 190/190, registry tests 118/118. Allowed-call latency unchanged (main and the patch measured back to back in the workspace: +3.9 / +5.2 ms and +3.9 / +5.4 ms). Shiwin's machine after Day 11: +5.5 ms p50 / +6.8 ms p95. LLM numbers are from Day 9.

**Repo:** github.com/boyndasouth/AgentGate (branch main, Day 11 at 4d0dd58) · **Broker:** https://agentgate-broker.onrender.com (Day 12 patch is OpenAPI v0.9.0) · **Admin UI:** Vercel, root dir `ui/` · **DB:** Supabase, session pooler; OpenFGA in its own `openfga` schema · **Slack:** two apps in one workspace, channel `C0CHR0W285R` · **Auth0:** one Regular Web App "AgentGate Admin", sign-ups disabled

## Day 12 checklist
- [x] **HTTP upstreams** (`broker/app/upstream.py`, `upstream.kind = "http"`): method, URL template with `{arg}` in the path only (one percent-encoded segment each), static headers, bearer or named-header auth, JSON or query arguments. HTTPS to public addresses only (resolved once, every address checked, connection pinned, certificate checked against the name); `UPSTREAM_PRIVATE_HOSTS` for local mocks. No redirects, timeout, size cap. Result `{status, ok, body}`; taints if `taints_session`.
- [x] **Credentials:** env vars named by `credential_ref`, which must be `UPSTREAM_*`. Never in a response, audit row, registry row, Slack message, log line or error text; scrubbed from upstream answers (echo test). A row whose credential is missing is unusable.
- [x] **Agent API:** `POST /agents` (row + owner tuple, `agent_registered`), `PATCH /agents/{id}` (display name, status = kill switch).
- [x] **Grant API:** `GET/POST/DELETE /agents/{id}/grants` with `{tool, mode, params}`; six modes, params validated per mode; `grant_added` / `grant_removed`. `POST/DELETE /tools/{name}/approvers` (`approver_added` / `approver_removed`).
- [x] **Tool API:** `POST/PATCH/DELETE /tools`; a row the gate can't fully understand is refused with the reason; changes audited as `registry_changed` with who made them. Egress, money and destructive tools default to `approval` grants; a direct grant must be named and comes back with a warning.
- [x] **Seed sync keeps API grants:** `grants` and `tool_approvers` tables; `seed_fga.py` syncs `tuples.yaml` ∪ those rows; the broker writes missing API tuples back at startup. Seed tuples can't be changed through the API (409).
- [x] **UI:** register an agent, add/remove grants (mode, params, risk class, warning before a direct grant on a risky tool), a Tools panel (register, switch on/off, approvers, problems). Writes go through server routes that add `X-Admin-Via` from the Auth0 session.
- [x] **`mock-upstream`** in compose (echo, CRM, email, payments, redirect, slow, big).
- [x] Tests: `broker/tests/test_day12.py` (190 checks) + `scripts/test_day12.ps1`; suite R01-R04; `eval/day12_check.py` for the Render redeploy check; UI smoke 46 checks.
- [x] Shiwin: applied `day12.patch` and pushed (2026-11-16)
- [x] Redeploy check on Render passed (2026-11-16): `setup`, Manual Deploy, `verify` (the API grant was still in OpenFGA and the call still allowed), `cleanup` (grant removed, the next call refused, tool removed); audit chain valid each time. `d12check-bot` stays registered with no grants.
- [ ] Commit the Render suite result (`eval/results/*.json`, 33/33)

## Day 12: apply and deploy
1. `git pull`, then `git apply --check day12.patch` and `git apply day12.patch`.
2. `docker compose up -d --build broker mock-upstream` (new compose service; no new Python requirement). In `docker compose logs broker`, look for `tool registry: 5 tools (5 enabled)` and `api grants: 0 written back to OpenFGA`. No policy change, so no `load_store.py` run.
3. `.\scripts\run_eval.ps1 suite` (expect 33/33: 14 blocked, 19 escalated), `.\scripts\test_day12.ps1` (expect 190/190; the seed-sync check prints "skipped" in the broker image, which has no PyYAML: that part is checked on Render in step 6), `.\scripts\test_registry.ps1` (expect 118/118), `.\scripts\demo_day2.ps1`.
4. UI: `cd ui; npm run check; npm run build`; optional `python tests/mock_broker.py 8765` + `node tests/smoke.mjs` (46 checks). Then open the local UI: Agents → `+ Register agent`, `+ Grant`; Tools → `+ Register tool`.
5. Commit and push. Render rebuilds the broker; the new tables are created at boot (nothing to run in the SQL editor). In the deploy log, after `15 sanity checks passed`, the seed line now reads `seed tuples=12 + api tuples=N`; on this first boot it also says the `grants` table isn't created yet. Vercel rebuilds the UI. Deploy order doesn't matter much: until Render is live, the new UI's forms get a 404/405 from the old broker, and the old UI never calls the new endpoints.
6. `.\scripts\run_eval.ps1 suite -Target render` (33/33). Then the redeploy check, in the eval container (Windows `py` failed to reach Render with a hidden error): `docker run --rm -v "${PWD}:/w" -w /w python:3.12-slim python eval/day12_check.py setup --target render`, Render → Manual Deploy, wait until live, the same command with `verify`, then with `cleanup`. Commit `eval/results/*.json`.
7. Optional, a real upstream on Render: add `UPSTREAM_<NAME>` in the dashboard (redeploys), register an `http` tool naming it, grant it. Plain http and private addresses are refused there by design.

## Day 12: tested before delivery (workspace: Postgres 16 as a non-superuser with CREATEROLE, OpenFGA v1.22.1 in memory, mock upstream, broker at the patch)
- Suite 33/33 (14 blocked, 19 escalated), no regressions in the 29 old cases, chain valid; the suite's tools and grants are gone afterwards.
- `test_day12.py` 190/190, twice in a row. Unit: 29 kinds of bad http row and 7 bad credential refs are unusable (no secret in any reason), path segments (`..`, `.`, control characters refused; `/`, `?`, `#` encoded), scrubbing in four encodings, a name resolving to loopback refused, every grant mode's params. Live: the done check (register `support-bot` + `crm.update_ticket`, grant, call: allowed, forwarded with the credential, audited; credential in no response, audit row or registry row, also when the upstream echoes it or the agent sends its value; grant removed → the next call with the same token denied), redirect not followed, timeout, size cap, PATCH audited with who did it, a taint switch honoured, risky defaults, seed tuples refused, API approver used for an approval that then ran the upstream call.
- Redeploy keeps API grants, three ways: `seed_fga.py` on the same store (grants kept), a Render boot simulation (fresh in-memory OpenFGA → `seed_fga.py` → broker; `api tuples=3`, `day12_check.py verify` passed), and a fresh store from `load_store.py --replace` followed by a broker restart ("2 written back").
- First boot on a Day 11 database: the seed skips the missing tables and syncs tuples.yaml as before. `schema.sql` run three times as the non-superuser: no errors, tool versions unchanged.
- TLS: a real HTTPS upstream through the pinned address answered 200; against a local TLS server with its own CA, the right name connected and a wrong name for the same address was refused (the sandbox's network proxy mints certificates per name, so this was tested offline).
- Concurrency: 20 identical grant requests → one 201, 19 × 409, one audit row; 10 parallel removals → one 200.
- Registry tests 118/118 (one Day 11 check updated: an http row is now refused for its real defect). Policy: 74/74 checks, 6/6 list_objects. Agents offline tests 14 passed. LLM self-test passed. UI: `svelte-check` 0 errors, `vite build` ok, smoke 46/46 (new routes, `X-Admin-Via` from the session, extra fields refused).
- Latency: main and the patch back to back, allowed call +3.9 / +5.2 ms and +3.9 / +5.4 ms.
- **Not tested:** Docker builds and compose (no Docker daemon here), the PowerShell scripts, Supabase and Render, Slack (an approval for an http tool posts the same summary as before), the UI in a browser (forms checked by svelte-check and the smoke test only; nothing looked at visually).

## Day 11 checklist
- [x] **`tools` table** (`broker/schema.sql`): `name`, `description`, `args_schema` (JSON Schema 2020-12), `risk_class`, `context_map`, `taints_session`, `upstream`, `credential_ref`, `enabled`, `version`, `created_by`, `created_at`, `updated_at`. Column defaults are the safe ones: a new row is disabled and taints the session.
- [x] **The five demo tools are rows** with `upstream: {"kind": "builtin"}`. `broker/app/tools.py` only keeps the mock implementations, keyed by name.
- [x] **Arguments are validated with `jsonschema`** (pinned 4.26.0). Unknown arguments are refused even when a schema leaves out `additionalProperties`. Size caps: 64 KiB body (413), 16,384 characters per string, 8 levels of nesting, 1,000 values. Reasons name the argument and never repeat a value or an odd argument name.
- [x] **The OpenFGA context is built from `context_map`** (`amount`, `url`, `recipient`, `payee`, `invoice`). Condition parameter names and the parsing (`policy_safe`, plain-address regex, URL host) are unchanged; they moved to `broker/app/registry.py`.
- [x] **Fails closed.** Unknown, disabled and misconfigured tools are refused before OpenFGA is asked. A row the broker can't fully understand (bad schema, `context_map` naming a missing, optional or wrongly typed argument, an upstream kind that isn't built yet) is kept with a `problem` and every call to it is denied. No token is issued for such a tool.
- [x] **Cache with refresh on change.** A statement trigger bumps `registry_state.version`; the gate compares it on every lookup (one primary-key read) and reloads when it differs. No restart needed, and it also catches edits made in the Supabase SQL editor.
- [x] **Registry changes are audited.** A reload that finds a difference writes `registry_changed` events ("enabled true -> false (version 1 -> 2)"). A row trigger bumps `version` only when something really changed.
- [x] **A tool disabled while an approval is pending** turns Approve into a deny, like the kill switch.
- [x] **`GET /tools`** (admin key): the registry as the gate sees it, with each row's `problem`.
- [x] Tests: `broker/tests/test_registry.py` (117 checks) and `scripts/test_registry.ps1`. The suite stays at 29 cases (see DECISIONS).
- [x] Shiwin: applied `day11.patch`, pushed, Render suite 29/29 with no regressions, local latency bench re-run (2026-11-16)
- [x] README latency updated to Shiwin's Day 11 run (+5.5 ms p50 / +6.8 ms p95, `eval/results/latency-local-20261117T014140Z.json`): `day11-readme.patch`

## Day 11: apply and deploy
1. `git pull`, then `git apply --check day11.patch` and `git apply day11.patch`.
2. `docker compose up -d --build broker` (a rebuild is needed: `jsonschema` is new in `requirements.txt`). The broker creates the `tools` table at startup. In `docker compose logs broker`, look for `tool registry: 5 tools (5 enabled)`. No policy change, so no `load_store.py` run.
3. `.\scripts\run_eval.ps1 suite` (expect 29/29), `.\scripts\test_registry.ps1` (expect 117/117), `.\scripts\demo_day2.ps1`.
4. Commit and push. Render rebuilds the broker and creates the table in Supabase at boot; nothing to run in the SQL editor. In the deploy log, look for `tool registry: 5 tools (5 enabled)` after the usual `15 sanity checks passed`.
5. `.\scripts\run_eval.ps1 suite -Target render`; commit `eval/results/*.json`. Do not run `test_registry.ps1` against Render: it edits rows.
6. Optional: `.\scripts\run_eval.ps1 bench` to see the registry's cost on your machine.

## Day 11: tested before delivery (workspace: Postgres 16 as a non-superuser with CREATEROLE, OpenFGA v1.22.1 in memory, broker at the patch on a fresh clone, fresh database)
- Suite 29/29 (11 blocked, 18 escalated), no regressions, chain valid. W10 still 404, W11 still 422 (reason is now "unexpected argument 'bcc'").
- `test_registry.py`: 117/117, run twice in a row (it restores every row). Unit: 20 kinds of bad row are unusable, 8 kinds of bad arguments are refused without a value in the reason, the context for each mapping, and the fail-closed cases (missing mapped argument, amount as string, bool, infinity, NaN or a huge integer). Live: schema mismatch, missing and extra arguments, unknown tool, string and body caps, schema defaults; a tool disabled in SQL is refused on the next call and gets no token; a `context_map` pointing at a missing argument denies with "failing closed"; `taints_session` switched off is honoured and audited; Approve on a tool disabled meanwhile becomes a deny; new rows are disabled by default; a tool with no grant gets no token; an `http` upstream is unusable.
- 40 parallel calls right after a row change: one reload, exactly one `registry_changed` row, chain valid.
- `schema.sql` run three times in a row as the non-superuser: no errors, row versions unchanged.
- Approve and replay through the registry: an outside email and a $250 payment against an invoice both ran after approval, and the invoice was settled. The Slack summary keeps the argument order (to, subject, body).
- Policy untouched: `fga model test` 74/74 checks, 6/6 list_objects. Agents offline tests: 14 passed. LLM self-test passed against the patched broker.
- Latency (workspace, 300 rounds): allowed call +3.0 ms p50 / +4.2 ms p95 on main, +3.1 / +4.1 with the patch.
- **Not tested:** Docker builds (`broker/Dockerfile`, `deploy/render/Dockerfile`) with the new requirement, `test_registry.ps1` itself (no PowerShell or Docker daemon here), Supabase (trigger creation through the session pooler), Render, Slack. The UI is untouched and its checks were not re-run.

## Day 10 checklist
- [x] **G05 closed (invoice matching).** The finance grant is now `within_limit_open_invoice`. A payment of $100 or less to an allowlisted payee from a clean session is allowed only when `invoice_id` names an OPEN invoice with the same payee and amount. The broker computes `invoice_matches` from Postgres and passes it in the check context. The invoice is settled in the same transaction as the payment, so paying it a second time escalates ("invoice INV-x is already paid"). Only admins create invoices (`POST/GET /invoices`). Seed: INV-1042, $40, acct_acme_supplies.
- [x] **Delegation chains.** `POST /delegations` (agent A grants a subset of its tools to agent B for 30-3600 s), `POST /tokens/exchange` (B trades its own token and the delegation id for a delegated token: `sub` = principal, nested `act`, `dlg` = chain). Calls are judged as the principal. Limits: max 2 hops, no cycles, same owner, a tainted session can't grant, and taint follows the grant. Every call re-checks each hop: the DB row (not revoked or expired) and OpenFGA (`delegate` with a `not_expired` condition, plus `covers`). Revoking one link cascades to everything below it, and the kill switch revokes every delegation that touches the agent. Admin: `GET /delegations`, `POST /delegations/{id}/revoke`.
- [x] **Persistent OpenFGA on Render.** When `FGA_DB_PASSWORD` is set, `deploy/render/fga_db.py` creates an `openfga` login role whose search_path is pinned to its own `openfga` schema (Supavisor ignores a search_path in the URL). The password is stored as a SCRAM verifier. OpenFGA runs `migrate`, then `seed_fga.py` SYNCS the store instead of recreating it: it reuses the model if unchanged and diff-syncs tool/agent tuples while keeping delegation tuples. Without the variable, OpenFGA stays in memory as before.
- [x] **UI cleanup.** `ui/src/lib/policy.ts` is deleted. `GET /agents` returns each agent's `grants` (read from OpenFGA) and `delegations`, and the Agents panel renders them with a Revoke button per delegation. The demo's payment creates an invoice first.
- [x] Suite: 29 cases. G05 now escalates; new G06 (pays an invoice id that doesn't exist) and D01-D06 (delegation abuse: over-broad grant, out-of-scope tool, chain past 2 hops, tainted grant, revoked link, kill switch on the delegator). LLM suite: 16 cases run, 13 n/a.
- [ ] Vercel and `audit-anchors`: can't be checked from the workspace. Shiwin: check Vercel → Deployments, filtered by branch `audit-anchors`.
- [x] Shiwin: applied `day10.patch` and `day10-fix1`, pushed, `FGA_DB_PASSWORD` set on Render, Render suite 29/29 (results committed, main at 10c5a19, 2026-11-16)
- [ ] Optional: re-run the LLM suite (G05 should now escalate)

## Day 10: apply and deploy
1. `git pull`, then `git apply --check day10.patch` and `git apply day10.patch`.
2. Supabase SQL editor: run the new parts of `broker/schema.sql` (the `invoices` and `delegations` tables, the new columns on `tokens` and `approvals`). The file is idempotent, so running all of it works too.
3. Local: `.\scripts\fga.ps1 model test --tests tests.fga.yaml` (74 checks, 6 list_objects), `py scripts/load_store.py --replace`, `docker compose up -d --build broker`, `.\scripts\run_eval.ps1 suite` (expect 29/29), `.\scripts\demo_day2.ps1`.
4. Render: add the secret `FGA_DB_PASSWORD` (16+ random characters), then push. In the deploy log, look for `[fga_db]` (role and schema ready), `openfga migrate`, and `[seed_fga] ... 15 sanity checks passed`. A second deploy should say the model is unchanged.
5. `.\scripts\run_eval.ps1 suite -Target render`; commit `eval/results/*.json`.

## Day 10: tested before delivery (workspace: Postgres 16, OpenFGA v1.22.1, broker at the patch, fresh database)
- `fga model test`: 74/74 checks, 6/6 list_objects. `model.json` is byte-identical to a fresh transform. `load_store.py --replace` replayed every case (delegation tests use contextual tuples). `seed_fga.py`: 15 sanity checks.
- Suite 29/29 (11 blocked, 18 escalated), no regressions, chain valid. Delegation integration test: 44 checks (grant limits, exchange, expiry, cascade, kill switch, approvals on a delegated call, audit labels). Day 8 and 9 recipient, payee and `via` tests pass; payee tests updated to pay against invoices. Anchoring publish and check pass.
- Render boot sequence against a SCRAM Postgres: role and schema created, OpenFGA tables only in `openfga` and no access to `public`, password rotation works, no secret in the PG log or the process list, an unchanged policy reuses the model, and a failure in fga_db or seed stops the boot.
- Agents offline tests: 14 passed. LLM self-test passed. UI smoke passed, `svelte-check` 0 errors, `vite build` ok. Short latency run: allowed calls +3.4 ms p50, invoice payment +0.7 ms over that.
- **Not tested:** login through Supabase's real Supavisor with the new role, Render latency with OpenFGA on Postgres, PowerShell scripts, a visual check of the new Agents panel, Vercel on `audit-anchors`.

## Day 9 checklist
- [x] **G04 closed (payee allowlist).** `transfer_funds` direct grant is now `within_limit_known_payee` (amount ≤ 100 AND clean session AND `to_account` in `[acct_acme_supplies]`, exact match). Replaces `within_limit_untainted`. Escalation reason says "payee is not on the allowlist" without the account number.
- [x] **New known gap G05** (duplicate-invoice fraud: $90 to the known payee in a new run → allowed). Suite: 22 cases, **21/22 stopped (7 blocked, 14 escalated, 1 allowed)** in the workspace.
- [x] **Control characters in policy context.** OpenFGA rejects a check whose context holds a control character, so `to_account: "x\n"` or a URL host with `\x07` gave a 503 "policy engine unavailable" (still a deny, but a wrong reason). `policy_safe()` in tools.py turns such values into '' (never on an allowlist). The host case existed since Day 7.
- [x] Callers moved to the allowlisted payee: UI demo (already `acct_acme_supplies`), `demo_day2.ps1` (`vendor-1042` → `acct_acme_supplies`), latency bench (`ACCT-BENCH` → `acct_acme_supplies`), orchestrator `pay` task (now names the account), offline FakeGate, UI mock broker.
- [x] **LLM-in-the-loop suite** (`eval/llm_cases.py`, `eval/llm_suite.py`, `scripts/run_llm_suite.ps1`): 16 of 22 cases run through the real agents; 6 are n/a (the agents' tools can't express them, or the orchestrator fixes the scopes). Reports "model tried it" vs. "got through". `-SelfTest` checks the harness with scripted models, no API key.
- [x] Shiwin: applied `day9.patch`; 63/63 + 5/5, suite 21/22 (G05), `demo_day2.ps1` all pass, LLM self-test passed in Docker (2026-11-16)
- [x] LLM run, Gemini 3.1 Flash-Lite, 3 trials: 48 runs, 13 provider errors (503/429), 35 valid; model tried the attack 14/35, through the gate 3/35 (all G05). Numbers in the README.
- [x] Day 9 pushed (main at cfabd2a)
- [ ] Optional: a second LLM batch when Gemini is less busy (several rows have 1 valid run); merge the result files
- [x] Day 8 leftover: the anchor workflow ran successfully; `audit-anchors` branch live, first anchor at row 291 (2026-11-16)
- [x] Stretch: delegation chains, done on Day 10

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
- Evals: `.\scripts\run_eval.ps1 suite|bench [-Target render]` (Docker, python:3.12-slim, stdlib only). Run any other `eval/*.py` the same way (`docker run --rm -v "${PWD}:/w" -w /w python:3.12-slim python eval/<script>.py ...`): Windows Python failed the HTTPS request to Render on Day 12, cause not found. The suite cancels its own escalations; with Slack on it still posts ~11 messages. The benchmark writes ~1,300 audit rows: run it locally, not against prod.
- Policy changes: edit `policy/`, run `.\scripts\fga.ps1 model test --tests tests.fga.yaml` (path relative to policy/), `.\scripts\export_model_json.ps1`, `py scripts/load_store.py --replace`, `docker compose up -d --build broker`; pushing redeploys Render, which reseeds OpenFGA at boot.
- Tamper beat (safe version): note the injection's `send_email` escalate row by `id` (highest id with tool_call / send_email / escalate), copy `decision` + `reason` first, edit, Verify names that id, paste back, Verify intact before moving on.

## Incident (2026-11-15, fixed)
- Prod `/audit/verify` reported row 1 modified: a past tamper beat had set row 1's `reason` (a `token_issued` row) to `policy: can_invoke ` and never restored it. Recovered the original by recomputing the hash against candidate task strings (`scopes: transfer_funds; task: Pay invoice INV-1042: $40.00 to Acme Supplies.`, matches `tokens.task` for the jti) and restored it with SQL. Chain valid again; no history lost.
- Supabase's SQL editor flags `$40` inside a string literal as an UPDATE without WHERE (its client-side parser trips on `$`); build the `$` with `chr(36)` instead.

## Open bugs / risks
- Day 12: the broker holds real upstream credentials now. A broker compromise exposes them. One env var per upstream; rotating one is a redeploy.
- Day 12: the admin key can register tools, grant them and approve calls. The UI records which Auth0 account acted; calls with the bare key are recorded as `admin-api`.
- Day 12: `test_day12.ps1` can't run the seed-sync check inside the broker image (no PyYAML); it is covered by `eval/day12_check.py` on Render.
- Day 12: the UI forms were not looked at in a browser before delivery.
- Day 11: registry changes made while the broker is down are not audited: it only sees the difference between two loads. Changes made in SQL are audited without a name.
- Day 11: one more query per tool call and per token request (the registry version). About +0.1 ms in the workspace; unmeasured on Render, where every query crosses the network to Supabase.
- Day 11: `pattern` rules in a tool's schema run as Python regexes. Whoever can edit the registry is trusted not to write a slow one.
- No known gap left in the suite. That doesn't mean no risk. Invoice matching trusts whoever creates invoices (the admin key, i.e. accounts payable). A fake invoice entered there passes, the same way it would in a real AP system.
- Every email to an outside address, every payment to a new account and every payment without an open invoice needs approval. Both allowlists are static (one entry each, in tuples.yaml).
- Delegation: a token minted in the same second as a kill switch counts as revoked (wait about 1 s before re-enabling). Delegated tokens live at most until the delegation expires. Revocation is checked on every call, so a revoked link stops the next call even with a valid token.
- Persistent OpenFGA shares the Supabase free-tier connection budget (max open conns 5, idle 2). Watch for "too many connections" on Render.
- URL allowlist is exact-match and static; a real read_web would need checks on every redirect hop.
- Anchoring window: rows after the latest anchor (up to 6 h) can be rewritten unnoticed until the next one. GitHub pauses scheduled workflows after 60 days without activity.
- `audit-anchors` branch: `ui/vercel.json` with `git.deploymentEnabled: false` should make Vercel skip it. Untested. If Vercel still builds it, set an Ignored Build Step.
- Carried:
  - Gemini free tier is flaky; the scripted demo is the fallback.
  - SvelteKit is pinned to 2.70.4 (never run `npm audit fix --force`).
  - Sign-out keeps the Auth0 session.
  - asyncpg pool vs the Supabase pooler.
  - The Supabase free project pauses after inactivity.
  - Render cold start takes about 1 minute.

## Next step
Apply `day12-followup.patch` (eval docs, clearer health error) and commit the Render suite results. Then Day 13 (agents log in as themselves), in a new chat. First decision: Auth0 M2M or hashed per-agent API keys (check the Auth0 free-tier M2M quota first).
