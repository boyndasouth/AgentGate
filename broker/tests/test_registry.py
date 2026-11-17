"""Day 11: tests for the tool registry (tools as rows in Postgres).

Two parts:
  unit   no network, no database: compiling rows, validating arguments, building the policy
         context. Runs anywhere the broker's requirements are installed.
  live   against a running LOCAL broker and its database. It edits the `tools` table directly
         (the way an admin with SQL access could), checks that the gate notices at once, and
         puts every row back. Never point it at production.

  .\\scripts\\test_registry.ps1              # both parts, in the broker's container
  .\\scripts\\test_registry.ps1 -UnitOnly
  python broker/tests/test_registry.py [--unit-only]   # needs DATABASE_URL + the broker's keys in the env

Exit code: 0 = all passed, 1 = a check failed, 2 = setup error.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # broker/ (or /srv in the container)

from app import registry  # noqa: E402
from app.registry import ArgsError, ContextError, compile_row, policy_inputs, validate  # noqa: E402

FAILED: list[str] = []
COUNT = 0


def check(name: str, ok: bool, detail: object = "") -> None:
    global COUNT
    COUNT += 1
    if not ok:
        FAILED.append(name)
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + (f"   [{detail}]" if detail and not ok else ""))


def row(**over) -> dict:
    base = {
        "name": "t.pay", "description": "", "risk_class": "money", "taints_session": False,
        "enabled": True, "version": 1, "credential_ref": None,
        "upstream": {"kind": "builtin", "handler": "transfer_funds"},
        "context_map": {"amount": "amount", "payee": "to_account", "invoice": "invoice_id"},
        "args_schema": {"type": "object", "required": ["amount", "to_account"], "additionalProperties": False,
                        "properties": {"amount": {"type": "number"}, "to_account": {"type": "string"},
                                       "memo": {"type": "string", "default": ""},
                                       "invoice_id": {"type": "string", "default": ""}}},
    }
    base.update(over)
    return base


def schema(**over) -> dict:
    s = json.loads(json.dumps(row()["args_schema"]))
    s.update(over)
    return s


def refused(tool, args) -> str:
    try:
        validate(tool, args)
    except ArgsError as exc:
        return str(exc)
    return ""


# ------------------------------------------------------------------ unit


def unit() -> None:
    print("unit: compiling registry rows")
    good = compile_row(row())
    check("a well-formed row is usable", good.usable and good.problem is None, good.problem)
    check("argument order: required first", good.arg_order[:2] == ("amount", "to_account"), good.arg_order)

    bad_rows = {
        "name with upper case": row(name="Pay"),
        "name too short": row(name="p"),
        "unknown risk class": row(risk_class="harmless"),
        "schema is not an object schema": row(args_schema={"type": "string"}),
        "schema allows unknown arguments": row(args_schema=schema(additionalProperties=True)),
        "schema with patternProperties": row(args_schema=schema(patternProperties={".*": {}})),
        "schema with a remote $ref": row(args_schema=schema(
            properties={**schema()["properties"], "memo": {"$ref": "https://evil.example/s.json"}})),
        "schema with $id": row(args_schema=schema(**{"$id": "https://evil.example/s.json"})),
        "schema that is not valid JSON Schema": row(args_schema=schema(required="amount")),
        "context_map: unknown key": row(context_map={"sum": "amount"}),
        "context_map: argument the schema doesn't declare": row(context_map={"amount": "total"}),
        "context_map: amount mapped to a string argument": row(context_map={"amount": "memo"}),
        "context_map: payee mapped to a number": row(context_map={"payee": "amount"}),
        "context_map: mapped argument is optional": row(context_map={"payee": "memo"}),
        "context_map is not an object": row(context_map=["amount"]),
        "upstream kind http (not built yet)": row(upstream={"kind": "http", "url": "https://api.example"}),
        "upstream kind unknown": row(upstream={"kind": "shell"}),
        "upstream missing": row(upstream=None),
        "builtin handler that doesn't exist": row(upstream={"kind": "builtin", "handler": "rm_rf"}),
        "default that breaks its own schema": row(args_schema=schema(
            properties={**schema()["properties"], "memo": {"type": "string", "default": 5}})),
    }
    for label, r in bad_rows.items():
        t = compile_row(r)
        check(f"unusable: {label}", t.problem is not None and not t.usable and t.unavailable_reason() is not None)
    check("a disabled row says so", "disabled" in (compile_row(row(enabled=False)).unavailable_reason() or ""))
    check("compile_row never raises on junk", compile_row({"name": 5, "args_schema": None}).problem is not None)

    print("unit: validating arguments")
    ok_args = {"amount": 40, "to_account": "acct_acme_supplies"}
    filled = validate(good, ok_args)
    check("defaults are filled in", filled == {**ok_args, "memo": "", "invoice_id": ""}, filled)
    check("the caller's dict is not changed", ok_args == {"amount": 40, "to_account": "acct_acme_supplies"})
    secret = "4111-1111-SECRET"
    cases = {
        "wrong type (amount as a string)": {"amount": "40", "to_account": "a"},
        "wrong type (amount true)": {"amount": True, "to_account": "a"},
        "wrong type (payee as a list)": {"amount": 1, "to_account": ["a", secret]},
        "wrong type (payee as an object)": {"amount": 1, "to_account": {"$ne": secret}},
        "missing required argument": {"amount": 1},
        "extra argument": {**ok_args, "bcc": secret},
        "arguments are a list": [1, 2],
        "arguments are null": None,
    }
    for label, args in cases.items():
        why = refused(good, args)
        check(f"refused: {label}", bool(why), why)
        check(f"  ... and the reason holds no value ({label})", secret not in why and "40" not in why, why)
    check("extra argument is named", "'bcc'" in refused(good, {**ok_args, "bcc": 1}))
    hostile = refused(good, {**ok_args, "x\nFAKE LOG LINE <b>": 1})
    check("a hostile argument NAME is not repeated", "FAKE" not in hostile and "\n" not in hostile, hostile)
    no_flag = compile_row(row(args_schema={k: v for k, v in schema().items() if k != "additionalProperties"}))
    check("a schema that omits additionalProperties still refuses extras",
          no_flag.usable and "unexpected" in refused(no_flag, {**ok_args, "bcc": 1}), no_flag.problem)
    check("string over the cap", "longer" in refused(good, {**ok_args, "memo": "x" * (registry.MAX_STRING_CHARS + 1)}))
    check("string at the cap passes", not refused(good, {**ok_args, "memo": "x" * registry.MAX_STRING_CHARS}))
    loose = compile_row(row(name="t.loose", context_map={}, upstream={"kind": "builtin", "handler": "read_inbox"},
                            args_schema={"type": "object", "properties": {"blob": {}}}))
    deep: object = "x"
    for _ in range(registry.MAX_DEPTH + 2):
        deep = [deep]
    check("nesting over the cap", "nested" in refused(loose, {"blob": deep}))
    check("too many values", "too many" in refused(loose, {"blob": list(range(registry.MAX_VALUES + 1))}))
    ranged = compile_row(row(args_schema=schema(
        properties={**schema()["properties"], "amount": {"type": "number", "maximum": 100}})))
    why = refused(ranged, {"amount": 5000, "to_account": "a"})
    check("other schema rules are named, not quoted", "'maximum'" in why and "5000" not in why, why)

    print("unit: building the policy context")
    ctx = policy_inputs(good, validate(good, {"amount": 40, "to_account": "acct_x", "invoice_id": "INV-1"}))
    check("amount, payee, invoice mapped", (ctx.amount, ctx.payee, ctx.invoice_id) == (40.0, "acct_x", "INV-1"), ctx)
    check("payee tool gets the payee reason, without the account",
          ctx.allowlist_reason == "payee is not on the allowlist")
    ctx = policy_inputs(good, validate(good, {"amount": 40, "to_account": "acct_x"}))
    check("no invoice given -> '' (a human decides)", ctx.invoice_id == "")
    check("payee with a control character -> ''",
          policy_inputs(good, {"amount": 1, "to_account": "acct\n"}).payee == "")

    def fails_closed(tool, args) -> bool:
        try:
            policy_inputs(tool, args)
        except ContextError:
            return True
        return False

    # A Tool built by hand, as if compile_row had been bypassed: the second lock must still hold.
    rogue = registry.Tool(name="t.rogue", enabled=True, context_map={"amount": "total", "payee": "to_account"})
    check("context_map -> missing argument fails closed", fails_closed(rogue, {"amount": 5, "to_account": "a"}))
    check("mapped amount is a string: fails closed", fails_closed(good, {"amount": "1", "to_account": "a"}))
    check("mapped amount is a bool: fails closed", fails_closed(good, {"amount": True, "to_account": "a"}))
    check("mapped amount is infinite: fails closed", fails_closed(good, {"amount": float("inf"), "to_account": "a"}))
    check("mapped amount is NaN: fails closed", fails_closed(good, {"amount": float("nan"), "to_account": "a"}))
    check("mapped amount is a huge integer: fails closed", fails_closed(good, {"amount": 10 ** 400, "to_account": "a"}))
    check("mapped payee is a list: fails closed", fails_closed(good, {"amount": 1, "to_account": ["a"]}))

    mail = compile_row(row(name="t.mail", risk_class="egress", context_map={"recipient": "to"},
                           upstream={"kind": "builtin", "handler": "send_email"},
                           args_schema={"type": "object", "required": ["to"], "properties": {"to": {"type": "string"}}}))
    dom = lambda to: policy_inputs(mail, {"to": to}).recipient_domain   # noqa: E731
    check("recipient domain, lowercased", dom("Ann@AgentGate.Example") == "agentgate.example")
    for odd in ("a@x.example, b@y.example", "Ann <a@x.example>", " a@x.example", "a@x.example.", "a@x.example\n", ""):
        check(f"recipient {odd!r} -> ''", dom(odd) == "")
    web = compile_row(row(name="t.web", risk_class="read", context_map={"url": "url"},
                          upstream={"kind": "builtin", "handler": "read_web"},
                          args_schema={"type": "object", "required": ["url"], "properties": {"url": {"type": "string"}}}))
    host = lambda url: policy_inputs(web, {"url": url}).host   # noqa: E731
    check("host parsed", host("https://Example.com./x") == "example.com")
    check("userinfo trick gives the real host", host("https://example.com@evil.example/") == "evil.example")
    for odd in ("ftp://example.com/", "javascript:alert(1)", "not a url", "https://exa\x07mple.com/"):
        check(f"url {odd!r} -> ''", host(odd) == "")
    plain = compile_row(row(name="t.plain", risk_class="read", context_map={},
                            upstream={"kind": "builtin", "handler": "read_inbox"},
                            args_schema={"type": "object", "properties": {"limit": {"type": "integer", "default": 5}}}))
    ctx = policy_inputs(plain, validate(plain, {}))
    check("a tool with no context_map sends neutral values",
          (ctx.amount, ctx.host, ctx.recipient_domain, ctx.payee, ctx.invoice_id, ctx.allowlist_reason)
          == (0.0, "", "", "", None, None), ctx)


# ------------------------------------------------------------------ live


class Live:
    def __init__(self) -> None:
        import httpx
        self.base = os.environ.get("AGENTGATE_URL", "http://localhost:8000").rstrip("/")
        self.orch = os.environ["AGENTGATE_ORCHESTRATOR_KEY"]
        self.admin_key = os.environ["AGENTGATE_ADMIN_KEY"]
        self.http = httpx.Client(timeout=30)
        self.db = None

    def mint(self, agent: str, scopes: list[str], session: str | None = None):
        body = {"agent_id": agent, "task": "registry-test", "scopes": scopes}
        if session:
            body["session_id"] = session
        r = self.http.post(f"{self.base}/tokens", json=body, headers={"X-Orchestrator-Key": self.orch})
        return r.status_code, r.json()

    def token(self, agent: str, scopes: list[str]) -> str:
        status, body = self.mint(agent, scopes)
        if status != 201:
            raise SystemExit(f"setup: token for {agent} refused ({status}): {body}")
        return body["access_token"]

    def call(self, token: str, tool: str, args, raw: bytes | None = None):
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        r = self.http.post(f"{self.base}/tools/{tool}", headers=headers,
                           content=raw if raw is not None else json.dumps({"args": args}).encode())
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, {}

    def admin(self, method: str, path: str, body: dict | None = None):
        r = self.http.request(method, f"{self.base}{path}", json=body, headers={"X-Admin-Key": self.admin_key})
        return r.status_code, r.json()

    async def sql(self, query: str, *args):
        return await self.db.execute(query, *args)

    async def last_events(self, n: int = 6) -> list[dict]:
        rows = await self.db.fetch("SELECT event_type, tool, decision, reason FROM audit_events ORDER BY id DESC LIMIT $1", n)
        return [dict(r) for r in rows]


async def live() -> None:
    import asyncpg
    g = Live()
    try:
        g.http.get(f"{g.base}/health").raise_for_status()
    except Exception as exc:   # noqa: BLE001
        raise SystemExit(f"setup: broker not reachable at {g.base}: {exc}") from None
    g.db = await asyncpg.connect(os.environ["DATABASE_URL"])
    await g.db.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")
    saved = [dict(r) for r in await g.db.fetch(
        "SELECT name, args_schema, context_map, taints_session, upstream, enabled FROM tools")]
    try:
        await _live(g)
    finally:
        # Put every seeded row back and remove the test rows, whatever happened above.
        await g.db.execute("DELETE FROM tools WHERE name LIKE 'regtest.%'")
        for r in saved:
            await g.db.execute(
                """UPDATE tools SET args_schema = $2, context_map = $3, taints_session = $4, upstream = $5,
                                    enabled = $6 WHERE name = $1""",
                r["name"], r["args_schema"], r["context_map"], r["taints_session"], r["upstream"], r["enabled"])
        g.admin("GET", "/tools")            # let the broker see (and audit) the restore
        await g.db.close()


async def _live(g: Live) -> None:
    print("live: the registry as served")
    status, tools = g.admin("GET", "/tools")
    by_name = {t["name"]: t for t in tools} if status == 200 else {}
    check("GET /tools lists the five demo tools",
          {"read_web", "read_inbox", "send_email", "transfer_funds", "query_customers"} <= set(by_name), status)
    check("all five are enabled and have no problem",
          all(by_name[n]["enabled"] and by_name[n]["problem"] is None for n in by_name if "." not in n))
    check("risk classes", (by_name.get("send_email", {}).get("risk_class"),
                           by_name.get("transfer_funds", {}).get("risk_class")) == ("egress", "money"))
    check("GET /tools needs the admin key", g.http.get(f"{g.base}/tools").status_code == 401)

    print("live: argument validation at the gate")
    fin = g.token("finance", ["transfer_funds"])
    mail = g.token("mailer", ["read_inbox", "query_customers", "send_email"])
    status, body = g.call(fin, "transfer_funds", {"amount": "40", "to_account": "acct_acme_supplies"})
    check("schema mismatch -> 422 deny", (status, body.get("decision")) == (422, "deny"), body)
    check("  ... reason names the argument, not the value",
          "'amount'" in body.get("reason", "") and "40" not in body.get("reason", ""), body.get("reason"))
    ev = (await g.last_events(1))[0]
    check("  ... and it is audited as a deny", (ev["event_type"], ev["decision"]) == ("tool_call", "deny"), ev)
    status, body = g.call(fin, "transfer_funds", {"amount": 5})
    check("missing required argument -> 422", status == 422 and "to_account" in body.get("reason", ""), body)
    status, body = g.call(mail, "send_email", {"to": "a@agentgate.example", "subject": "s", "body": "b",
                                               "bcc": "records@partner-archive.example"})
    check("extra argument -> 422", status == 422 and "'bcc'" in body.get("reason", ""), body)
    check("  ... the smuggled address is not in the reason", "partner-archive" not in body.get("reason", ""))
    status, body = g.call(mail, "send_email", {"to": ["a@agentgate.example", "x@evil.example"], "subject": "s", "body": "b"})
    check("recipient as a list -> 422", status == 422, body)
    status, body = g.call(mail, "admin_export", {"scope": "all"})
    check("unknown tool -> 404 deny", (status, body.get("decision")) == (404, "deny"), body)
    status, body = g.call(mail, "Read_Inbox", {})
    check("tool name with other casing -> 404", status == 404, body)
    status, body = g.call(mail, "send_email", {"to": "a@agentgate.example", "subject": "s",
                                               "body": "x" * (registry.MAX_STRING_CHARS + 1)})
    check("string over the cap -> 422", status == 422 and "longer" in body.get("reason", ""), body)
    big = json.dumps({"args": {"to": "a@agentgate.example", "subject": "s", "body": "x" * (registry.MAX_BODY_BYTES + 10)}})
    status, body = g.call(mail, "send_email", None, raw=big.encode())
    check("body over the cap -> 413", status == 413, status)
    status, body = g.call(mail, "read_inbox", {})
    check("schema default used (read_inbox with no args) -> 200", status == 200 and "messages" in body.get("result", {}), body)
    status, body = g.call(mail, "query_customers", {"limit": 2})
    check("query_customers still works", status == 200 and len(body["result"]["customers"]) == 2, body)

    print("live: a tool disabled in the table (no restart)")
    await g.sql("UPDATE tools SET enabled = false WHERE name = 'query_customers'")
    status, body = g.call(mail, "query_customers", {"limit": 2})
    check("disabled tool -> 403 deny on the very next call",
          (status, body.get("decision")) == (403, "deny") and "disabled" in body.get("reason", ""), body)
    events = await g.last_events(3)
    check("  ... the change is in the audit log",
          any(e["event_type"] == "registry_changed" and e["tool"] == "query_customers"
              and "enabled true -> false" in e["reason"] and re.search(r"version \d+ -> \d+", e["reason"])
              for e in events), events)
    status, body = g.mint("mailer", ["query_customers"])
    check("no new token for a disabled tool", status == 400 and "disabled" in body.get("reason", ""), body)
    await g.sql("UPDATE tools SET enabled = true WHERE name = 'query_customers'")
    status, body = g.call(mail, "query_customers", {"limit": 1})
    check("re-enabled -> works again", status == 200, body)
    before = await g.db.fetchval("SELECT version FROM tools WHERE name = 'query_customers'")
    n_before = await g.db.fetchval("SELECT count(*) FROM audit_events WHERE event_type = 'registry_changed'")
    await g.sql("UPDATE tools SET description = description WHERE name = 'query_customers'")
    g.call(mail, "query_customers", {"limit": 1})
    after = await g.db.fetchval("SELECT version FROM tools WHERE name = 'query_customers'")
    n_after = await g.db.fetchval("SELECT count(*) FROM audit_events WHERE event_type = 'registry_changed'")
    check("an UPDATE that changes nothing: no new version, no audit row", (before, n_before) == (after, n_after),
          (before, after, n_before, n_after))

    print("live: context_map pointing at a missing argument")
    await g.sql("""UPDATE tools SET context_map = '{"amount": "total", "payee": "to_account", "invoice": "invoice_id"}'
                   WHERE name = 'transfer_funds'""")
    status, body = g.call(fin, "transfer_funds", {"amount": 5, "to_account": "acct_acme_supplies"})
    check("-> 403 deny, failing closed",
          (status, body.get("decision")) == (403, "deny") and "misconfigured" in body.get("reason", "")
          and "failing closed" in body.get("reason", ""), body)
    status, tools = g.admin("GET", "/tools")
    check("  ... GET /tools shows the problem",
          "context_map.amount" in (next(t for t in tools if t["name"] == "transfer_funds")["problem"] or ""))
    await g.sql("""UPDATE tools SET context_map = '{"amount": "amount", "payee": "to_account", "invoice": "invoice_id"}'
                   WHERE name = 'transfer_funds'""")
    status, body = g.call(fin, "transfer_funds", {"amount": 5, "to_account": "acct_acme_supplies"})
    check("restored -> the policy decides again (no invoice: escalate)", (status, body.get("decision")) == (202, "escalate"), body)
    if body.get("approval_id"):
        g.http.post(f"{g.base}/approvals/{body['approval_id']}/cancel", headers={"Authorization": f"Bearer {fin}"})

    print("live: taints_session switched off in the table")
    await g.sql("UPDATE tools SET taints_session = false WHERE name = 'read_inbox'")
    t2 = g.token("mailer", ["read_inbox"])
    status, body = g.call(t2, "read_inbox", {})
    check("the read no longer taints (the row is the source of truth)", status == 200 and body.get("session_tainted") is False, body)
    events = await g.last_events(4)
    check("  ... and the edit is audited",
          any(e["event_type"] == "registry_changed" and e["tool"] == "read_inbox"
              and "taints_session true -> false" in e["reason"] for e in events), events)
    await g.sql("UPDATE tools SET taints_session = true WHERE name = 'read_inbox'")
    t3 = g.token("mailer", ["read_inbox"])
    status, body = g.call(t3, "read_inbox", {})
    check("switched back on -> taints again", status == 200 and body.get("session_tainted") is True, body)

    print("live: a tool disabled while its approval is pending")
    t4 = g.token("mailer", ["send_email"])
    status, body = g.call(t4, "send_email", {"to": "x@outside.example", "subject": "s", "body": "b"})
    check("outside recipient escalates", (status, body.get("decision")) == (202, "escalate"), body)
    approval = body.get("approval_id")
    await g.sql("UPDATE tools SET enabled = false WHERE name = 'send_email'")
    status, body = g.admin("POST", f"/approvals/{approval}/decision", {"approve": True, "approver": "shiwin"})
    check("Approve turns into a deny", status == 200 and body.get("status") == "denied", body)
    ev = (await g.last_events(1))[0]
    check("  ... and the audit row says why",
          ev["event_type"] == "approval_resolved" and ev["decision"] == "deny" and "disabled" in ev["reason"], ev)
    await g.sql("UPDATE tools SET enabled = true WHERE name = 'send_email'")
    status, body = g.call(t4, "send_email", {"to": "a@agentgate.example", "subject": "s", "body": "b"})
    check("re-enabled: an internal send goes through", status == 200, body)

    print("live: new rows are safe by default")
    insert = """INSERT INTO tools (name, args_schema, risk_class, context_map, upstream, enabled, created_by)
                VALUES ($1, $2, $3, $4, $5, $6, 'registry-test')"""
    obj = {"type": "object", "properties": {"limit": {"type": "integer", "default": 1}}}
    await g.db.execute("INSERT INTO tools (name, args_schema, risk_class, upstream, created_by) "
                       "VALUES ('regtest.defaults', $1, 'read', $2, 'registry-test')", obj, {"kind": "builtin", "handler": "read_inbox"})
    r = dict(await g.db.fetchrow("SELECT enabled, taints_session, version FROM tools WHERE name = 'regtest.defaults'"))
    check("column defaults: disabled, taints the session", r == {"enabled": False, "taints_session": True, "version": 1}, r)
    await g.db.execute(insert, "regtest.echo", obj, "read", {}, {"kind": "builtin", "handler": "query_customers"}, True)
    status, body = g.mint("mailer", ["regtest.echo"])
    check("enabled tool with no grant: no token", status == 403 and "may not hold" in body.get("reason", ""), body)
    events = await g.last_events(4)
    check("  ... the new row is audited", any(e["event_type"] == "registry_changed" and e["tool"] == "regtest.echo"
                                              and "tool added" in e["reason"] for e in events), events)
    await g.db.execute(insert, "regtest.http", obj, "write", {}, {"kind": "http", "url": "https://api.example/x"}, True)
    await g.db.execute(insert, "regtest.openschema", {**obj, "additionalProperties": True}, "read", {},
                       {"kind": "builtin", "handler": "read_inbox"}, True)
    status, tools = g.admin("GET", "/tools")
    probs = {t["name"]: t["problem"] for t in tools}
    check("an http upstream is unusable for now", "not supported" in (probs.get("regtest.http") or ""), probs)
    check("a schema that allows unknown arguments is unusable", "additionalProperties" in (probs.get("regtest.openschema") or ""), probs)
    status, body = g.mint("mailer", ["regtest.http"])
    check("no token for a misconfigured tool", status == 400, body)
    try:
        await g.db.execute(insert, "Bad Name", obj, "read", {}, {"kind": "builtin"}, True)
        check("the table refuses a bad tool name", False)
    except Exception:   # noqa: BLE001  (asyncpg.CheckViolationError)
        check("the table refuses a bad tool name", True)
    await g.sql("DELETE FROM tools WHERE name = 'regtest.echo'")
    status, tools = g.admin("GET", "/tools")
    check("a deleted row disappears at once", "regtest.echo" not in {t["name"] for t in tools})
    events = await g.last_events(3)
    check("  ... and the removal is audited", any(e["tool"] == "regtest.echo" and "removed" in e["reason"] for e in events), events)

    time.sleep(0.2)
    chain = g.http.get(f"{g.base}/audit/verify").json()
    check("audit chain still valid", chain.get("valid") is True, chain)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--unit-only", action="store_true")
    args = ap.parse_args()
    unit()
    if not args.unit_only:
        missing = [k for k in ("DATABASE_URL", "AGENTGATE_ORCHESTRATOR_KEY", "AGENTGATE_ADMIN_KEY") if not os.environ.get(k)]
        if missing:
            print(f"setup: missing in the environment: {', '.join(missing)} (or pass --unit-only)")
            return 2
        asyncio.run(live())
    print(f"\n{COUNT - len(FAILED)}/{COUNT} checks passed" + (f"; FAILED: {', '.join(FAILED)}" if FAILED else ""))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
