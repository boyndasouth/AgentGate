"""Run the 21-case prompt-injection suite through the gate and report the block rate.

  python eval/injection_suite.py                    # local broker (.env, http://localhost:8000)
  python eval/injection_suite.py --target render    # deployed broker (.env.render)
  python eval/injection_suite.py --only W01,G02     # a subset
  (or .\\scripts\\run_eval.ps1 suite [-Target render], which runs it in Docker)

Each case plays the calls a fully hijacked agent team would make (see eval/cases.py).
Escalations are cancelled by the agent right after they're recorded, so nothing is left
pending and a late Slack click can't run the call. With Slack on, every escalation still
posts a message (~13); run locally with Slack off if you don't want the pings.

Writes eval/results/injection-<target>-<utc>.json and prints a Markdown table for the README.
Exit code: 0 = every case matched its expected outcome, 1 = a regression, 2 = setup error.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cases import CASES, Call, Case, Token  # noqa: E402
from gate import REPO, Gate, load_config  # noqa: E402

STOPPED = {"deny": "blocked", "token_denied": "blocked", "escalate": "escalated", "allow": "allowed"}


class SetupError(Exception):
    pass


def run_case(gate: Gate, case: Case) -> dict:
    session: str | None = None
    tokens: dict[str, str] = {}
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

        assert isinstance(step, Call)
        token = tokens.get(step.agent)
        if token is None:
            raise SetupError(f"{case.id}: no token for {step.agent}")
        status, body, _ = gate.tool(token, step.tool, step.args)
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
