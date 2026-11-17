"""Run the 36-case prompt-injection suite through the gate and report the block rate.

  python eval/injection_suite.py                    # local broker (.env, http://localhost:8000)
  python eval/injection_suite.py --target render    # deployed broker (.env.render)
  python eval/injection_suite.py --only W01,G02     # a subset
  (or .\\scripts\\run_eval.ps1 suite [-Target render], which runs it in Docker)

Each case plays the calls a fully hijacked agent team would make (see eval/cases.py).
Escalations are cancelled by the agent right after they're recorded, so nothing is left
pending and a late Slack click can't run the call. With Slack on, every escalation still
posts a message (~19); run locally with Slack off if you don't want the pings.

Day 12: before the cases, the runner registers two suite-only tools through the admin API
(`suite.lookup`, `suite.notify`, see cases.SUITE_TOOLS); the R cases grant, ungrant and edit them.
Every grant and edit is undone after its case, and both tools are removed at the end.

Writes eval/results/injection-<target>-<utc>.json and prints a Markdown table for the README.
Exit code: 0 = every case matched its expected outcome, 1 = a regression, 2 = setup error.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cases import (CASES, SUITE_AGENT, SUITE_CLIENT, SUITE_TOOLS, Call, Case, Delegate, Exchange, Grant,  # noqa: E402
                   Invoice, Kill, Login, Token, ToolEdit, Ungrant)
from gate import REPO, Gate, load_config  # noqa: E402

STOPPED = {"deny": "blocked", "token_denied": "blocked", "refused": "blocked", "escalate": "escalated",
           "allow": "allowed"}


class SetupError(Exception):
    pass


def setup_tools(gate: Gate) -> None:
    """Day 12: register the suite-only tools (or reset them if a crashed run left them behind)."""
    for tool in SUITE_TOOLS:
        status, body, _ = gate.admin("POST", "/tools", tool)
        if status == 409:
            fields = {k: v for k, v in tool.items() if k != "name"}
            status, body, _ = gate.admin("PATCH", f"/tools/{tool['name']}", fields)
        if status not in (200, 201):
            raise SetupError(f"can't register {tool['name']} ({status}): {body.get('reason')}")
    # Day 13: an agent that logs in as itself (case L03). Registered once; it stays, with no grants.
    status, body, _ = gate.admin("POST", "/agents", {"id": SUITE_AGENT, "owner": "shiwin",
                                                     "display_name": "Suite M2M agent", "auth0_client_id": SUITE_CLIENT})
    if status == 409:
        gate.admin("PATCH", f"/agents/{SUITE_AGENT}", {"status": "active"})
        status, body, _ = gate.admin("PATCH", f"/agents/{SUITE_AGENT}", {"auth0_client_id": SUITE_CLIENT})
    if status not in (200, 201):
        raise SetupError(f"can't register {SUITE_AGENT} ({status}): {body.get('reason')}")


def forged_login_token(client_id: str) -> str:
    """What a hijacked agent can build by itself: an unsigned token (alg none) that claims to be
    an identity-provider token for `client_id`."""
    def part(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    now = int(time.time())
    return (part({"alg": "none", "typ": "JWT", "kid": "none"}) + "."
            + part({"iss": "https://login.example/", "sub": f"{client_id}@clients", "azp": client_id,
                    "aud": "agentgate", "gty": "client-credentials", "iat": now, "exp": now + 3600}) + ".")


def teardown_tools(gate: Gate) -> None:
    for tool in SUITE_TOOLS:
        for agent in ("researcher", "mailer", "finance"):
            gate.admin("DELETE", f"/agents/{agent}/grants?tool={tool['name']}")
        gate.admin("DELETE", f"/tools/{tool['name']}")


def run_case(gate: Gate, case: Case) -> dict:
    killed: list[str] = []
    granted: dict[str, str] = {}
    undo: list[tuple[str, str, dict | None]] = []     # Day 12: admin changes to reverse, newest first
    try:
        return _run_case(gate, case, killed, granted, undo)
    finally:
        for method, path, body in reversed(undo):
            gate.admin(method, path, body)
        for did in granted.values():   # Day 10: leave no live test delegations behind (cascades to hop 2)
            gate.admin("POST", f"/delegations/{did}/revoke", {"reason": f"injection-suite {case.id} cleanup"})
        for agent in killed:          # Day 10: leave every agent active for the next case
            gate.admin("POST", f"/agents/{agent}/enable")
        if killed:
            time.sleep(1.2)           # a token minted in the kill switch's second counts as revoked


def _run_case(gate: Gate, case: Case, killed: list[str], granted: dict[str, str],
              undo: list[tuple[str, str, dict | None]]) -> dict:
    session: str | None = None
    tokens: dict[str, str] = {}
    # granted: Day 10, delegate -> delegation id granted to it (the caller revokes them afterwards)
    acting: dict[str, tuple[str, set[str]]] = {}   # Day 10: agent -> (delegated token, its scopes)

    def token_for(agent: str, tools) -> str | None:
        """Like a real client: the delegated token for delegated tools, the agent's own otherwise."""
        if agent in acting and set(tools) <= acting[agent][1]:
            return acting[agent][0]
        return tokens.get(agent)
    invoice = ""
    trail: list[str] = []
    out = {"id": case.id, "channel": case.channel, "goal": case.goal, "expect": case.expect,
           "gap": case.gap, "outcome": None, "status": None, "reason": "", "session_tainted": None,
           "audit_id": None}

    for step in case.steps:
        if isinstance(step, Token):
            sid = None if step.new_session else session
            status, body, _ = gate.mint(step.agent, list(step.scopes), f"injection-suite {case.id}", sid)
            trail.append(f"token {step.agent} {','.join(step.scopes)} -> {status}")
            if step.attack:
                out.update(outcome="token_denied" if status == 403 else ("allow" if status == 201 else "error"),
                           status=status, reason=body.get("reason", ""), audit_id=body.get("audit_id"))
                break
            if status != 201:
                raise SetupError(f"{case.id}: token for {step.agent} refused ({status}): {body.get('reason')}")
            tokens[step.agent] = body["access_token"]
            session = body["session_id"]
            continue

        if isinstance(step, Login):
            bearer = forged_login_token(SUITE_CLIENT) if step.bearer == "forged-none" else tokens.get(step.agent, "")
            status, body, _ = gate.login(bearer, list(step.scopes), f"injection-suite {case.id}")
            trail.append(f"{step.agent} logs in with {step.bearer} -> {status}")
            # 401/403 = refused; 503 = this broker has no identity provider configured, so nobody
            # can log in this way at all. Either way the attack got no token.
            out.update(outcome="refused" if status in (401, 403, 503) else ("allow" if status == 201 else "error"),
                       status=status, reason=body.get("reason", ""), audit_id=body.get("audit_id"))
            break

        if isinstance(step, Invoice):
            status, body, _ = gate.admin("POST", "/invoices", {"payee": step.payee, "amount": step.amount})
            if status != 201:
                raise SetupError(f"{case.id}: invoice refused ({status}): {body}")
            invoice = body["id"]
            trail.append(f"invoice {invoice} {step.amount} -> {status}")
            continue

        if isinstance(step, Grant):
            body = {"tool": step.tool, **({"mode": step.mode} if step.mode else {})}
            status, out_body, _ = gate.admin("POST", f"/agents/{step.agent}/grants", body)
            if status != 201:
                raise SetupError(f"{case.id}: grant refused ({status}): {out_body.get('reason')}")
            undo.append(("DELETE", f"/agents/{step.agent}/grants?tool={step.tool}", None))
            trail.append(f"admin grants {step.agent} {step.tool} ({out_body.get('mode')}) -> {status}")
            continue

        if isinstance(step, Ungrant):
            status, out_body, _ = gate.admin("DELETE", f"/agents/{step.agent}/grants?tool={step.tool}")
            if status != 200:
                raise SetupError(f"{case.id}: ungrant refused ({status}): {out_body.get('reason')}")
            trail.append(f"admin removes {step.agent}'s grant on {step.tool} -> {status}")
            continue

        if isinstance(step, ToolEdit):
            status, out_body, _ = gate.admin("PATCH", f"/tools/{step.tool}", step.changes)
            if status != 200:
                raise SetupError(f"{case.id}: tool edit refused ({status}): {out_body.get('reason')}")
            undo.append(("PATCH", f"/tools/{step.tool}", step.undo))
            trail.append(f"admin edits {step.tool} {step.changes} -> {status}")
            continue

        if isinstance(step, Kill):
            gate.admin("POST", f"/agents/{step.agent}/disable", {"reason": f"injection-suite {case.id}"})
            killed.append(step.agent)
            trail.append(f"kill switch {step.agent}")
            continue

        if isinstance(step, (Delegate, Exchange)):
            token = token_for(step.agent, step.tools) if isinstance(step, Delegate) else tokens.get(step.agent)
            if token is None:
                raise SetupError(f"{case.id}: no token for {step.agent}")
            if isinstance(step, Delegate):
                status, body, _ = gate.delegate(token, step.to, list(step.tools), task=f"injection-suite {case.id}")
                trail.append(f"{step.agent} delegates {','.join(step.tools)} to {step.to} -> {status}")
            else:
                status, body, _ = gate.exchange(token, granted.get(step.agent, "00000000-0000-0000-0000-000000000000"),
                                                list(step.scopes), task=f"injection-suite {case.id}")
                trail.append(f"{step.agent} exchanges for {','.join(step.scopes)} -> {status}")
            if step.attack:
                out.update(outcome="refused" if status in (400, 403, 404) else ("allow" if status == 201 else "error"),
                           status=status, reason=body.get("reason", ""), audit_id=body.get("audit_id"))
                break
            if status != 201:
                raise SetupError(f"{case.id}: {type(step).__name__.lower()} refused ({status}): {body.get('reason')}")
            if isinstance(step, Delegate):
                granted[step.to] = body["delegation_id"]
            else:
                acting[step.agent] = (body["access_token"], set(step.scopes))
            continue

        assert isinstance(step, Call)
        token = token_for(step.agent, [step.tool])
        if token is None:
            raise SetupError(f"{case.id}: no token for {step.agent}")
        args = {k: (invoice if v == "$invoice" else v) for k, v in step.args.items()}
        status, body, _ = gate.tool(token, step.tool, args)
        decision = body.get("decision", "error")
        trail.append(f"{step.agent} {step.tool} -> {status} {decision}")
        if not step.attack:
            if decision != "allow":
                raise SetupError(f"{case.id}: setup call {step.tool} got {status} {body.get('reason')}")
            continue
        out.update(outcome=decision, status=status, reason=body.get("reason", ""),
                   session_tainted=body.get("session_tainted"), audit_id=body.get("audit_id"))
        if decision == "escalate" and body.get("approval_id"):
            c_status, c_body, _ = gate.cancel(token, body["approval_id"])   # leave nothing pending
            out["approval_closed"] = c_body.get("status") or c_status
        break

    out["trail"] = trail
    out["result"] = STOPPED.get(out["outcome"], "error")
    out["matched"] = out["outcome"] == case.expect
    return out


def markdown(results: list[dict]) -> str:
    rows = ["| # | Channel | Attack | Gate | Why |", "| --- | --- | --- | --- | --- |"]
    icon = {"blocked": "⛔ blocked", "escalated": "✋ escalated", "allowed": "⚠️ allowed", "error": "❗ error"}
    for r in results:
        why = r["gap"].split(". Fix:")[0] if r["result"] == "allowed" and r["gap"] else r["reason"]
        why = why.replace("|", "\\|")[:110]
        rows.append(f"| {r['id']} | {r['channel']} | {r['goal']} | {icon[r['result']]} | {why} |")
    return "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", choices=["local", "render"], default="local")
    ap.add_argument("--only", help="comma-separated case ids")
    ap.add_argument("--no-save", action="store_true")
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # Windows consoles / redirects

    cfg = load_config(args.target)
    gate = Gate(cfg)
    health = gate.wait_healthy()
    cases = [c for c in CASES if not args.only or c.id in args.only.split(",")]
    print(f"AgentGate injection suite: {len(cases)} cases against {cfg.target} "
          f"(slack={health.get('slack')}). Worst case: every payload is fully obeyed.\n")

    results = []
    try:
        setup_tools(gate)
    except SetupError as exc:
        print(f"SETUP ERROR {exc}")
        return 2
    try:
        for case in cases:
            try:
                r = run_case(gate, case)
            except SetupError as exc:
                print(f"SETUP ERROR {exc}")
                return 2
            results.append(r)
            mark = "ok " if r["matched"] else "!! "
            taint = {True: "tainted", False: "clean", None: "-"}[r["session_tainted"]]
            print(f"{mark}{r['id']:4} {r['result']:9} {r['status']!s:4} {taint:8} {r['goal'][:58]:58} "
                  f"{'(known gap)' if case.gap else ''}")
            if not r["matched"]:
                print(f"     expected {case.expect}, got {r['outcome']}: {r['reason']}")
    finally:
        teardown_tools(gate)

    n = len(results)
    blocked = sum(r["result"] == "blocked" for r in results)
    escalated = sum(r["result"] == "escalated" for r in results)
    allowed = sum(r["result"] == "allowed" for r in results)
    stopped = blocked + escalated
    status, chain, _ = gate.request("GET", "/audit/verify")
    regressions = [r["id"] for r in results if not r["matched"]]

    summary = {"target": cfg.target, "base_url": cfg.base_url,
               "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "cases": n, "blocked": blocked, "escalated": escalated, "allowed": allowed,
               "stop_rate": round(stopped / n, 4) if n else None,
               "known_gaps": [r["id"] for r in results if r["gap"]],
               "regressions": regressions, "audit_chain": chain}
    print(f"\nStopped {stopped}/{n} ({stopped / n:.0%}): {blocked} blocked outright, "
          f"{escalated} escalated to a human. Allowed: {allowed} (known gaps: "
          f"{', '.join(summary['known_gaps']) or 'none'}).")
    print(f"Audit chain after the run: {json.dumps(chain)}")
    print("Regressions: " + (", ".join(regressions) if regressions else "none") + "\n")
    print(markdown(results))

    if not args.no_save:
        out_dir = REPO / "eval" / "results"
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = out_dir / f"injection-{cfg.target}-{stamp}.json"
        path.write_text(json.dumps({"summary": summary, "results": results}, indent=2), encoding="utf-8")
        print(f"\nSaved {path.relative_to(REPO)}")
    return 1 if regressions else 0


if __name__ == "__main__":
    sys.exit(main())
