"""Day 12: HTTP upstreams, upstream credentials, and the agent / grant / tool admin API.

  unit   no network, no database: http upstream rows, URL building, credential scrubbing,
         grant modes and their params.
  live   against a running LOCAL broker, its database and the mock upstream
         (deploy/mock-upstream/server.py). Runs the Day 12 done check: register `support-bot` and an
         http tool `crm.update_ticket`, grant it, call it (allowed, forwarded, audited), check the
         credential appears nowhere, remove the grant (the next call is denied), and check that a
         boot-time seed sync keeps API-made grants. Removes its test tools and grants at the end;
         the `support-bot` agent stays registered (agents are disabled, never deleted).

  .\\scripts\\test_day12.ps1              # both parts, in the broker's container
  .\\scripts\\test_day12.ps1 -UnitOnly
  python broker/tests/test_day12.py [--unit-only]
      env: DATABASE_URL, AGENTGATE_ADMIN_KEY, AGENTGATE_ORCHESTRATOR_KEY, UPSTREAM_MOCK_TOKEN,
           AGENTGATE_URL (default http://broker:8000), MOCK_UPSTREAM_URL (default http://mock-upstream:9090),
           FGA_API_URL (for the seed-sync check)

Never point it at production: it registers tools and changes grants. Exit 0 = all passed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))     # broker/ (or /srv in the container)

from app import grants, registry, upstream  # noqa: E402
from app.grants import GrantError  # noqa: E402
from app.registry import ArgsError, compile_row, validate  # noqa: E402

FAILED: list[str] = []
COUNT = 0
SECRET = "unit-test-secret-0123456789"
ENV = {"UPSTREAM_TEST": SECRET, "UPSTREAM_SHORT": "abc", "UPSTREAM_SPACE": "has a space in it",
       "UPSTREAM_PRIVATE_HOSTS": "mock-upstream"}


def check(name: str, ok: bool, detail: object = "") -> None:
    global COUNT
    COUNT += 1
    if not ok:
        FAILED.append(name)
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + (f"   [{detail}]" if detail and not ok else ""))


SCHEMA = {"type": "object", "required": ["ticket_id", "status"], "additionalProperties": False,
          "properties": {"ticket_id": {"type": "string"}, "status": {"type": "string"},
                         "note": {"type": "string"}, "count": {"type": "integer"}}}


def up(**over) -> dict:
    base = {"kind": "http", "method": "PATCH", "url": "https://crm.example.com/api/tickets/{ticket_id}"}
    base.update(over)
    return base


def plan_problem(upstream_row: dict, credential_ref="UPSTREAM_TEST", schema=SCHEMA) -> str | None:
    return upstream.compile_http(upstream_row, schema, credential_ref, ENV)[1]


# ------------------------------------------------------------------ unit


def unit() -> None:
    print("unit: http upstream rows")
    plan, why = upstream.compile_http(up(), SCHEMA, "UPSTREAM_TEST", ENV)
    check("a well-formed http row compiles", why is None and plan is not None, why)
    check("  ... bearer auth by default when a credential is named", plan and plan.auth == "bearer")
    check("  ... PATCH sends its arguments as JSON", plan and plan.send_args == "json")
    check("  ... the placeholder is found", plan and plan.path_args == ("ticket_id",))
    check("GET sends its arguments in the query",
          upstream.compile_http(up(method="GET"), SCHEMA, "UPSTREAM_TEST", ENV)[0].send_args == "query")
    check("plain http to a host in UPSTREAM_PRIVATE_HOSTS is allowed",
          plan_problem(up(url="http://mock-upstream:9090/t/{ticket_id}")) is None)

    bad = {
        "plain http to a public host": up(url="http://crm.example.com/t"),
        "placeholder in the host": up(url="https://{ticket_id}.example.com/t"),
        "placeholder in the query": up(url="https://crm.example.com/t?id={ticket_id}"),
        "user and password in the URL": up(url="https://user:pw@crm.example.com/t"),
        "@ in the authority": up(url="https://crm.example.com@evil.example/t"),
        "fragment": up(url="https://crm.example.com/t#x"),
        "loopback address": up(url="https://127.0.0.1/t"),
        "cloud metadata address": up(url="https://169.254.169.254/latest"),
        "private 10/8 address": up(url="https://10.1.2.3/t"),
        "IPv6 loopback": up(url="https://[::1]/t"),
        "ftp scheme": up(url="ftp://crm.example.com/t"),
        "space in the URL": up(url="https://crm.example.com/a b"),
        "non-ASCII host": up(url="https://crm.exämple.com/t"),
        "placeholder naming an undeclared argument": up(url="https://crm.example.com/t/{nope}"),
        "placeholder naming an optional argument": up(url="https://crm.example.com/t/{note}"),
        "malformed placeholder": up(url="https://crm.example.com/t/{ticket_id"),
        "unknown method": up(method="TRACE"),
        "unknown key": up(follow_redirects=True),
        "reserved header Host": up(headers={"Host": "evil.example"}),
        "reserved header Authorization": up(headers={"Authorization": "Bearer x"}),
        "reserved header Cookie": up(headers={"Cookie": "a=b"}),
        "header value with a newline": up(headers={"X-A": "a\r\nX-B: b"}),
        "header that carries the credential set statically": up(auth={"type": "header", "name": "X-Api-Key"},
                                                                 headers={"x-api-key": "static"}),
        "auth header name that is reserved": up(auth={"type": "header", "name": "Cookie"}),
        "unknown auth type": up(auth={"type": "basic"}),
        "GET with a JSON body": up(method="GET", send_args="json"),
        "timeout too long": up(timeout_seconds=600),
        "timeout as a bool": up(timeout_seconds=True),
        "response cap too big": up(max_response_bytes=50_000_000),
    }
    for label, row in bad.items():
        check(f"refused: {label}", plan_problem(row) is not None)
    creds = {
        "credential_ref that isn't UPSTREAM_*": "AGENTGATE_ADMIN_KEY",
        "credential_ref = DATABASE_URL": "DATABASE_URL",
        "credential_ref = UPSTREAM_PRIVATE_HOSTS": "UPSTREAM_PRIVATE_HOSTS",
        "credential_ref not set in the environment": "UPSTREAM_MISSING",
        "credential too short": "UPSTREAM_SHORT",
        "credential with a space": "UPSTREAM_SPACE",
        "credential_ref lower case": "upstream_test",
    }
    for label, ref in creds.items():
        why = plan_problem(up(), credential_ref=ref)
        check(f"refused: {label}", why is not None, why)
        check(f"  ... and the reason holds no secret", why is None or SECRET not in why and "abc" not in why.split("'")[-1])
    check("refused: auth none with a credential_ref", plan_problem(up(auth={"type": "none"})) is not None)
    check("refused: bearer auth with no credential_ref", plan_problem(up(auth={"type": "bearer"}), credential_ref=None) is not None)
    check("allowed: no auth and no credential", plan_problem(up(), credential_ref=None) is None)

    print("unit: the registry with http rows")
    row = {"name": "crm.update_ticket", "risk_class": "write", "taints_session": False, "enabled": True,
           "args_schema": SCHEMA, "context_map": {}, "upstream": up(url="http://mock-upstream:9090/t/{ticket_id}"),
           "credential_ref": "UPSTREAM_TEST"}
    os.environ.update({k: v for k, v in ENV.items()})
    tool = compile_row(row)
    check("an http row is usable", tool.usable and tool.http is not None, tool.problem)
    check("an mcp row is still unusable", compile_row({**row, "upstream": {"kind": "mcp"}}).problem is not None)
    check("a credential_ref that isn't a string is unusable", compile_row({**row, "credential_ref": 5}).problem is not None)
    for label, value in {"'..'": "..", "'.'": ".", "empty": "", "a newline": "T-1\n", "a NUL": "T\x00"}.items():
        try:
            validate(tool, {"ticket_id": value, "status": "open"})
            check(f"path argument {label} -> 422", False)
        except ArgsError as exc:
            check(f"path argument {label} -> 422", "'ticket_id'" in str(exc))
    try:
        validate(tool, {"ticket_id": "T-1", "status": "open"})
        check("an ordinary path argument passes", True)
    except ArgsError as exc:
        check("an ordinary path argument passes", False, exc)
    check("a slash stays inside one segment", upstream._segment("t", "../../payments") == "..%2F..%2Fpayments")
    check("a query character stays inside one segment", upstream._segment("t", "a?b=c#d") == "a%3Fb%3Dc%23d")
    check("an integer argument works", upstream._segment("t", 42) == "42")

    print("unit: scrubbing the credential from upstream output")
    import base64
    import urllib.parse
    for label, form in {"as is": SECRET, "url-encoded": urllib.parse.quote(SECRET, safe=""),
                        "base64": base64.b64encode(SECRET.encode()).decode(),
                        "JSON-escaped": json.dumps(SECRET)[1:-1]}.items():
        out = upstream.redact(f'{{"echo": "Bearer {form}"}}', SECRET)
        check(f"credential removed ({label})", SECRET not in out and form not in out and upstream.REDACTED in out, out)

    print("unit: a host that resolves to a private address")
    p, why = upstream.compile_http(up(url="https://localhost/t/{ticket_id}"), SCHEMA, "UPSTREAM_TEST", ENV)
    try:
        asyncio.run(upstream.call(p, "UPSTREAM_TEST", {"ticket_id": "T-1", "status": "x"}))
        check("a public-looking name that resolves to loopback is refused", False)
    except upstream.UpstreamError as exc:
        check("a public-looking name that resolves to loopback is refused", "private" in str(exc), exc)

    print("unit: grant modes")
    check("default for egress, money, destructive is approval",
          {grants.default_mode(r) for r in ("egress", "money", "destructive")} == {"approval"})
    check("default for write is direct_if_untainted", grants.default_mode("write") == "direct_if_untainted")
    check("default for read is direct", grants.default_mode("read") == "direct")
    params_ok = {
        "direct": {}, "direct_if_untainted": None, "approval": {},
        "direct_allowlisted_recipient": {"allowed_recipient_domains": ["AgentGate.example"]},
        "direct_known_payee_with_invoice": {"max_amount": 100, "allowed_payees": ["acct_acme_supplies"]},
        "direct_allowed_host": {"allowed_hosts": ["example.com"]},
    }
    for mode, params in params_ok.items():
        try:
            grants.clean_params(mode, params)
            check(f"params accepted: {mode}", True)
        except GrantError as exc:
            check(f"params accepted: {mode}", False, exc.reason)
    check("domains are lower-cased",
          grants.clean_params("direct_allowlisted_recipient", params_ok["direct_allowlisted_recipient"])
          == {"allowed_recipient_domains": ["agentgate.example"]})
    params_bad = {
        "params on a mode that takes none": ("direct", {"x": 1}),
        "missing param": ("direct_allowed_host", {}),
        "extra param": ("direct_allowed_host", {"allowed_hosts": ["a.example"], "x": 1}),
        "wildcard domain": ("direct_allowlisted_recipient", {"allowed_recipient_domains": ["*.example"]}),
        "domain without a dot": ("direct_allowlisted_recipient", {"allowed_recipient_domains": ["localhost"]}),
        "host with a port": ("direct_allowed_host", {"allowed_hosts": ["example.com:443"]}),
        "empty list": ("direct_allowed_host", {"allowed_hosts": []}),
        "not a list": ("direct_allowed_host", {"allowed_hosts": "example.com"}),
        "max_amount 0": ("direct_known_payee_with_invoice", {"max_amount": 0, "allowed_payees": ["a"]}),
        "max_amount as a string": ("direct_known_payee_with_invoice", {"max_amount": "100", "allowed_payees": ["a"]}),
        "max_amount infinite": ("direct_known_payee_with_invoice", {"max_amount": float("inf"), "allowed_payees": ["a"]}),
        "payee with a control character": ("direct_known_payee_with_invoice", {"max_amount": 5, "allowed_payees": ["a\n"]}),
        "params not an object": ("approval", [1]),
    }
    for label, (mode, params) in params_bad.items():
        try:
            grants.clean_params(mode, params)
            check(f"params refused: {label}", False)
        except GrantError as exc:
            check(f"params refused: {label}", exc.status == 400)
    key = grants.tuple_key("support-bot", "crm.update_ticket", "direct_if_untainted", {})
    check("tuple for direct_if_untainted", key == {"user": "agent:support-bot", "relation": "direct_invoker",
                                                   "object": "tool:crm.update_ticket", "condition": {"name": "untainted"}}, key)
    check("each mode maps back from its tuple", all(grants.mode_of(m.relation, m.condition) == n for n, m in grants.MODES.items()))
    check("payee accounts are counted, not listed, in the audit text",
          "acct_acme" not in grants.describe("direct_known_payee_with_invoice",
                                             {"max_amount": 100.0, "allowed_payees": ["acct_acme_supplies"]}))
    for raw, ok in {"shiwin": True, "user:shiwin": True, "user:Shiwin": False, "agent:x": False, "": False}.items():
        try:
            grants.user_id(raw)
            check(f"user id {raw!r}", ok)
        except GrantError:
            check(f"user id {raw!r}", not ok)


# ------------------------------------------------------------------ live


class Live:
    def __init__(self) -> None:
        import httpx
        self.base = os.environ.get("AGENTGATE_URL", "http://broker:8000").rstrip("/")
        self.mock = os.environ.get("MOCK_UPSTREAM_URL", "http://mock-upstream:9090").rstrip("/")
        self.admin_key = os.environ["AGENTGATE_ADMIN_KEY"]
        self.orch_key = os.environ["AGENTGATE_ORCHESTRATOR_KEY"]
        self.secret = os.environ["UPSTREAM_MOCK_TOKEN"]
        self.http = httpx.Client(timeout=60)
        self.seen: list[str] = []          # every response body, to look for the credential afterwards

    def _j(self, r):
        self.seen.append(r.text)
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, {}

    def admin(self, method: str, path: str, body=None, via: str | None = None, **params):
        headers = {"X-Admin-Key": self.admin_key, **({"X-Admin-Via": via} if via else {})}
        return self._j(self.http.request(method, f"{self.base}{path}", json=body, headers=headers, params=params or None))

    def mint(self, agent: str, scopes: list[str], session_id: str | None = None):
        body = {"agent_id": agent, "task": "day12 test", "scopes": scopes, **({"session_id": session_id} if session_id else {})}
        return self._j(self.http.post(f"{self.base}/tokens", json=body, headers={"X-Orchestrator-Key": self.orch_key}))

    def call(self, token: str, tool: str, args: dict):
        return self._j(self.http.post(f"{self.base}/tools/{tool}", json={"args": args},
                                      headers={"Authorization": f"Bearer {token}"}))

    def requests_seen(self) -> list[dict]:
        return self.http.get(f"{self.mock}/requests").json()


TEST_TOOLS = ("crm.update_ticket", "d12.echo", "d12.redirect", "d12.slow", "d12.big", "d12.notify",
              "d12.wipe", "d12.lookup")


def http_tool(name: str, method: str, path: str, *, risk: str = "write", schema: dict | None = None,
              context_map: dict | None = None, taints: bool = False, **extra) -> dict:
    mock = os.environ.get("MOCK_UPSTREAM_URL", "http://mock-upstream:9090").rstrip("/")
    return {"name": name, "description": f"day12 test: {method} {path}", "risk_class": risk,
            "args_schema": schema or {"type": "object", "additionalProperties": False, "properties": {}},
            "context_map": context_map or {}, "taints_session": taints, "enabled": True,
            "credential_ref": "UPSTREAM_MOCK_TOKEN",
            "upstream": {"kind": "http", "method": method, "url": mock + path, **extra}}


async def live() -> None:
    import asyncpg
    g = Live()
    for url in (g.base + "/health", g.mock + "/health"):
        try:
            g.http.get(url).raise_for_status()
        except Exception as exc:   # noqa: BLE001
            raise SystemExit(f"setup: {url} not reachable: {exc}") from None
    db = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        await _live(g, db)
    finally:
        for name in TEST_TOOLS:
            for agent in ("support-bot", "mailer"):
                g.admin("DELETE", f"/agents/{agent}/grants", tool=name)
            g.admin("DELETE", f"/tools/{name}/approvers/user:shiwin")
            g.admin("DELETE", f"/tools/{name}")
        await db.close()


async def last_events(db, n: int = 5) -> list[dict]:
    rows = await db.fetch("SELECT event_type, agent_id, tool, decision, reason, approver FROM audit_events "
                          "ORDER BY id DESC LIMIT $1", n)
    return [dict(r) for r in rows]


async def _live(g: Live, db) -> None:
    print("live: registering an agent")
    status, body = g.admin("POST", "/agents", {"id": "support-bot", "owner": "user:shiwin",
                                               "display_name": "Support bot"}, via="admin-ui:auth0|day12test")
    check("POST /agents registers support-bot (or it already exists)", status in (201, 409), body)
    if status == 201:
        ev = (await last_events(db, 1))[0]
        check("  ... audited as agent_registered, with who did it",
              (ev["event_type"], ev["approver"]) == ("agent_registered", "admin-ui:auth0|day12test"), ev)
    status, agents = g.admin("GET", "/agents")
    bot = next((a for a in agents if a["id"] == "support-bot"), {}) if status == 200 else {}
    check("  ... it is listed, active, with its owner", (bot.get("status"), bot.get("owner")) == ("active", "user:shiwin"), bot)
    for label, body in {"upper-case id": {"id": "Bot", "owner": "shiwin"},
                        "id with a slash": {"id": "a/b", "owner": "shiwin"},
                        "bad owner": {"id": "bot-x", "owner": "agent:mailer"},
                        "control character in the name": {"id": "bot-x", "owner": "shiwin", "display_name": "a‮b"},
                        "unknown field": {"id": "bot-x", "owner": "shiwin", "admin": True}}.items():
        status, _ = g.admin("POST", "/agents", body)
        check(f"POST /agents refuses: {label}", status == 400, status)
    status, _ = g.admin("POST", "/agents", {"id": "support-bot", "owner": "shiwin"})
    check("registering it twice -> 409", status == 409, status)
    status, _ = g.admin("POST", "/agents", {"id": "bot-x", "owner": "shiwin"}, via="slack:U123")
    check("a forged X-Admin-Via label -> 400", status == 400, status)
    check("POST /agents needs the admin key", g.http.post(f"{g.base}/agents", json={"id": "bot-y", "owner": "shiwin"}).status_code == 401)
    status, body = g.admin("PATCH", "/agents/support-bot", {"display_name": "Support bot (day 12)"})
    check("PATCH /agents changes the display name", status == 200 and body.get("display_name") == "Support bot (day 12)", body)

    print("live: registering an http tool")
    crm = http_tool("crm.update_ticket", "PATCH", "/crm/tickets/{ticket_id}", schema=SCHEMA)
    status, body = g.admin("POST", "/tools", crm)
    check("POST /tools registers crm.update_ticket", status == 201 and body.get("problem") is None, body)
    check("  ... the response names the credential, never its value",
          body.get("credential_ref") == "UPSTREAM_MOCK_TOKEN" and g.secret not in json.dumps(body))
    ev = (await last_events(db, 1))[0]
    check("  ... audited as registry_changed, with who did it",
          ev["event_type"] == "registry_changed" and "tool added" in ev["reason"] and ev["approver"] == "admin-api", ev)
    status, _ = g.admin("POST", "/tools", crm)
    check("registering it twice -> 409", status == 409)
    refused = {
        "credential_ref naming the admin key": {**crm, "name": "d12.bad", "credential_ref": "AGENTGATE_ADMIN_KEY"},
        "credential_ref naming DATABASE_URL": {**crm, "name": "d12.bad", "credential_ref": "DATABASE_URL"},
        "credential_ref that isn't set": {**crm, "name": "d12.bad", "credential_ref": "UPSTREAM_NOT_SET_ANYWHERE"},
        "plain http to a public host": {**crm, "name": "d12.bad", "upstream": {**crm["upstream"], "url": "http://example.com/x"}},
        "https to a private address": {**crm, "name": "d12.bad", "upstream": {**crm["upstream"], "url": "https://10.0.0.5/x"}},
        "an argument in the host": {**crm, "name": "d12.bad",
                                    "upstream": {**crm["upstream"], "url": "https://{ticket_id}.example.com/x"}},
        "a schema that allows extra arguments": {**crm, "name": "d12.bad", "args_schema": {**SCHEMA, "additionalProperties": True}},
        "an mcp upstream": {**crm, "name": "d12.bad", "upstream": {"kind": "mcp"}},
        "a bad name": {**crm, "name": "Bad Name"},
        "an unknown field": {**crm, "name": "d12.bad", "owner": "x"},
    }
    for label, body in refused.items():
        status, out = g.admin("POST", "/tools", body)
        check(f"POST /tools refuses {label} (400)", status == 400, (status, out))
    status, tools = g.admin("GET", "/tools")
    check("  ... and none of them was stored", not any(t["name"] == "d12.bad" for t in tools))

    print("live: grants")
    status, body = g.mint("support-bot", ["crm.update_ticket"])
    check("no grant yet -> no token (403)", status == 403, body)
    status, body = g.admin("POST", "/agents/support-bot/grants", {"tool": "crm.update_ticket"})
    check("a grant without a mode on a write tool -> direct_if_untainted",
          status == 201 and body.get("mode") == "direct_if_untainted" and body.get("defaulted") is True, body)
    ev = (await last_events(db, 1))[0]
    check("  ... audited as grant_added", (ev["event_type"], ev["agent_id"], ev["tool"]) ==
          ("grant_added", "support-bot", "crm.update_ticket"), ev)
    status, again = g.admin("POST", "/agents/support-bot/grants", {"tool": "crm.update_ticket", "mode": "direct"})
    check("a second direct grant on the same tool -> 409", status == 409, again)
    status, listed = g.admin("GET", "/agents/support-bot/grants")
    check("GET /agents/{id}/grants shows it, from the API", status == 200 and any(
        x["tool"] == "crm.update_ticket" and x["grant_mode"] == "direct_if_untainted" and x["source"] == "api"
        for x in listed), listed)

    print("live: calling the http tool (the done check)")
    status, tok = g.mint("support-bot", ["crm.update_ticket"])
    check("token for support-bot", status == 201, tok)
    token, session = tok.get("access_token", ""), tok.get("session_id")
    status, body = g.call(token, "crm.update_ticket", {"ticket_id": "T-1042", "status": "solved", "note": "fixed"})
    result = body.get("result") or {}
    check("call -> 200 allow, forwarded", status == 200 and body.get("decision") == "allow", body)
    check("  ... the upstream's answer reaches the agent",
          result.get("status") == 200 and result.get("body", {}).get("ticket") == "T-1042"
          and result.get("body", {}).get("updated") == {"status": "solved", "note": "fixed"}, result)
    last = g.requests_seen()[-1]
    check("  ... the upstream got the credential (from the broker, not the agent)", last["auth"] == "ok", last)
    check("  ... with the PATCH, path and Host it was configured with",
          (last["method"], last["path"], last["host"].split(":")[0]) ==
          ("PATCH", "/crm/tickets/T-1042", g.mock.split("//")[1].split(":")[0]), last)
    ev = (await last_events(db, 1))[0]
    check("  ... audited as an allowed tool_call", (ev["event_type"], ev["decision"], ev["tool"]) ==
          ("tool_call", "allow", "crm.update_ticket"), ev)
    status, body = g.call(token, "crm.update_ticket", {"ticket_id": "../../payments", "status": "x"})
    last = g.requests_seen()[-1]
    check("a path argument with ../ stays inside the ticket segment",
          status == 200 and last["path"] == "/crm/tickets/..%2F..%2Fpayments", last)
    status, body = g.call(token, "crm.update_ticket", {"ticket_id": "..", "status": "x"})
    check("a path argument '..' -> 422 before the policy is asked", status == 422 and body.get("decision") == "deny", body)
    status, body = g.call(token, "crm.update_ticket", {"ticket_id": "T-1", "status": "x", "url": "https://evil.example"})
    check("an extra argument -> 422", status == 422, body)

    print("live: the credential is visible nowhere")
    echo = http_tool("d12.echo", "POST", "/echo", schema={"type": "object", "additionalProperties": False,
                                                          "properties": {"msg": {"type": "string"}}})
    g.admin("POST", "/tools", echo)
    g.admin("POST", "/agents/support-bot/grants", {"tool": "d12.echo", "mode": "direct"})
    status, tok2 = g.mint("support-bot", ["d12.echo"], session)
    status, body = g.call(tok2.get("access_token", ""), "d12.echo", {"msg": "hello"})
    echoed = (body.get("result") or {}).get("body") or {}
    check("an upstream that echoes its request headers works", status == 200 and echoed.get("body") == {"msg": "hello"}, body)
    check("  ... and the credential it echoed is scrubbed",
          echoed.get("headers", {}).get("Authorization") == f"Bearer {upstream.REDACTED}", echoed.get("headers"))
    status, body = g.call(tok2.get("access_token", ""), "d12.echo", {"msg": g.secret})
    check("an agent that sends the credential's value gets it scrubbed back too", g.secret not in json.dumps(body))
    for path in ("/tools", "/agents", "/audit/events?limit=200", "/approvals?status=all"):
        g.admin("GET", path.split("?")[0], **dict([path.split("?")[1].split("=")] if "?" in path else []))
    check("the credential is in no response the broker gave in this test", not any(g.secret in t for t in g.seen))
    rows = await db.fetch("SELECT * FROM audit_events")
    check("the credential is in no audit row", not any(g.secret in json.dumps(dict(r), default=str) for r in rows))
    rows = await db.fetch("SELECT * FROM tools")
    check("the credential is in no registry row", not any(g.secret in json.dumps(dict(r), default=str) for r in rows))

    print("live: upstreams that misbehave")
    for tool in (http_tool("d12.redirect", "GET", "/redirect"),
                 http_tool("d12.slow", "GET", "/slow?s=5", timeout_seconds=1),
                 http_tool("d12.big", "GET", "/big?kb=64", max_response_bytes=4096)):
        status, body = g.admin("POST", "/tools", tool)
        check(f"registered {tool['name']}", status == 201, body)
        g.admin("POST", "/agents/support-bot/grants", {"tool": tool["name"], "mode": "direct"})
    status, tok3 = g.mint("support-bot", ["d12.redirect", "d12.slow", "d12.big"], session)
    t3 = tok3.get("access_token", "")
    before = len(g.requests_seen())
    status, body = g.call(t3, "d12.redirect", {})
    check("a redirect -> 502, not followed", status == 502 and "redirect" in body.get("reason", ""), body)
    seen = g.requests_seen()
    check("  ... the upstream saw one request, nothing went to the redirect target",
          len(seen) == min(before + 1, 50) and seen[-1]["path"] == "/redirect", seen[-2:])
    status, body = g.call(t3, "d12.slow", {})
    check("a slow upstream -> 502 after the timeout", status == 502 and "within 1 s" in body.get("reason", ""), body)
    status, body = g.call(t3, "d12.big", {})
    check("an answer over the size cap -> 502", status == 502 and "larger than 4096" in body.get("reason", ""), body)
    ev = (await last_events(db, 1))[0]
    check("  ... audited as allowed with the upstream error", ev["decision"] == "allow" and "upstream error" in ev["reason"], ev)

    print("live: changing a tool through the API")
    status, body = g.admin("PATCH", "/tools/crm.update_ticket", {"credential_ref": "UPSTREAM_NOT_SET_ANYWHERE"})
    check("PATCH to a credential that isn't set -> 400, row unchanged", status == 400, body)
    status, body = g.admin("PATCH", "/tools/crm.update_ticket", {"taints_session": True}, via="admin-ui:auth0|day12test")
    check("PATCH taints_session", status == 200 and body.get("taints_session") is True, body)
    ev = (await last_events(db, 1))[0]
    check("  ... audited with old and new value and who did it",
          "taints_session false -> true" in ev["reason"] and ev["approver"] == "admin-ui:auth0|day12test", ev)
    status, body = g.call(token, "crm.update_ticket", {"ticket_id": "T-1", "status": "x"})
    check("the next call taints the session", status == 200 and body.get("session_tainted") is True, body)
    status, body = g.call(token, "crm.update_ticket", {"ticket_id": "T-1", "status": "x"})
    check("  ... and then the clean-session-only grant denies", status == 403 and "clean session" in body.get("reason", ""), body)
    g.admin("PATCH", "/tools/crm.update_ticket", {"taints_session": False})
    status, body = g.admin("PATCH", "/tools/crm.update_ticket", {"enabled": False})
    check("PATCH enabled false", status == 200 and body.get("enabled") is False)
    status, tok4 = g.mint("support-bot", ["crm.update_ticket"])
    check("a disabled tool gets no token", status == 400, tok4)
    g.admin("PATCH", "/tools/crm.update_ticket", {"enabled": True})
    status, body = g.admin("DELETE", "/tools/crm.update_ticket")
    check("a tool with grants can't be deleted (409)", status == 409, body)

    print("live: removing a grant")
    status, tok5 = g.mint("support-bot", ["crm.update_ticket"])
    t5 = tok5.get("access_token", "")
    status, body = g.call(t5, "crm.update_ticket", {"ticket_id": "T-2", "status": "open"})
    check("before: allowed", status == 200, body)
    status, body = g.admin("DELETE", "/agents/support-bot/grants", tool="crm.update_ticket")
    check("DELETE the grant", status == 200 and body.get("removed", [{}])[0].get("mode") == "direct_if_untainted", body)
    ev = (await last_events(db, 1))[0]
    check("  ... audited as grant_removed", ev["event_type"] == "grant_removed", ev)
    status, body = g.call(t5, "crm.update_ticket", {"ticket_id": "T-2", "status": "open"})
    check("the next call with the SAME token -> 403 deny", status == 403 and "no grant" in body.get("reason", ""), body)
    status, body = g.admin("DELETE", "/agents/support-bot/grants", tool="crm.update_ticket")
    check("removing it again -> 404", status == 404, body)

    print("live: risky tools default to a human")
    notify = http_tool("d12.notify", "POST", "/email/send", risk="egress", context_map={"recipient": "to"},
                       schema={"type": "object", "required": ["to", "body"], "additionalProperties": False,
                               "properties": {"to": {"type": "string"}, "body": {"type": "string"}}})
    g.admin("POST", "/tools", notify)
    status, body = g.admin("POST", "/agents/support-bot/grants", {"tool": "d12.notify"})
    check("an egress tool granted without a mode -> approval", status == 201 and body.get("mode") == "approval", body)
    check("  ... with a warning that no approver is set", "no approver" in (body.get("warning") or ""), body)
    status, body = g.admin("POST", "/agents/support-bot/grants",
                           {"tool": "d12.notify", "mode": "direct_allowlisted_recipient",
                            "params": {"allowed_recipient_domains": ["agentgate.example"]}})
    check("a narrower direct grant next to it, asked for by name", status == 201 and body.get("warning") is None, body)
    status, body = g.admin("POST", "/tools/d12.notify/approvers", {"user": "shiwin"})
    check("POST /tools/{name}/approvers", status == 201, body)
    status, tok6 = g.mint("support-bot", ["d12.notify"])
    t6 = tok6.get("access_token", "")
    status, body = g.call(t6, "d12.notify", {"to": "team@agentgate.example", "body": "hi"})
    check("mail to the allowlisted domain -> allowed", status == 200, body)
    status, body = g.call(t6, "d12.notify", {"to": "someone@outside.example", "body": "hi"})
    check("mail anywhere else -> escalate", status == 202 and body.get("approval_id"), body)
    status, dec = g.admin("POST", f"/approvals/{body.get('approval_id')}/decision", {"approve": True, "approver": "user:shiwin"})
    check("approved by the API-added approver -> the broker runs the call",
          status == 200 and dec.get("status") == "approved", dec)
    status, polled = g._j(g.http.get(f"{g.base}/approvals/{body.get('approval_id')}", headers={"Authorization": f"Bearer {t6}"}))
    check("  ... and the agent gets the upstream's answer", (polled.get("result") or {}).get("body", {}).get("status") == "queued", polled)

    wipe = http_tool("d12.wipe", "DELETE", "/echo/all", risk="destructive")
    g.admin("POST", "/tools", wipe)
    status, body = g.admin("POST", "/agents/support-bot/grants", {"tool": "d12.wipe"})
    check("a destructive tool granted without a mode -> approval", status == 201 and body.get("mode") == "approval", body)
    status, body = g.admin("POST", "/agents/mailer/grants", {"tool": "d12.wipe", "mode": "direct"})
    check("a direct grant on it, asked for by name -> allowed, with a warning",
          status == 201 and "destructive" in (body.get("warning") or ""), body)
    ev = (await last_events(db, 1))[0]
    check("  ... and the audit row says so", "direct grant on a destructive tool" in ev["reason"], ev)

    print("live: the seed file and the API don't overwrite each other")
    status, body = g.admin("POST", "/agents/mailer/grants", {"tool": "send_email", "mode": "approval"})
    check("a grant that tuples.yaml already sets -> 409", status == 409 and "tuples.yaml" in body.get("reason", ""), body)
    status, body = g.admin("DELETE", "/agents/mailer/grants", tool="read_inbox")
    check("removing a seed grant through the API -> 409", status == 409 and "tuples.yaml" in body.get("reason", ""), body)
    status, body = g.admin("DELETE", "/tools/send_email/approvers/user:shiwin")
    check("removing a seed approver through the API -> 409", status == 409, body)
    status, body = g.admin("POST", "/agents/support-bot/grants",
                           {"tool": "d12.echo", "mode": "direct_allowlisted_recipient",
                            "params": {"allowed_recipient_domains": ["agentgate.example"]}})
    check("a recipient mode on a tool that maps no recipient -> 400", status in (400, 409), body)
    status, body = g.admin("POST", "/agents/nobody/grants", {"tool": "d12.echo"})
    check("a grant for an unknown agent -> 404", status == 404)
    status, body = g.admin("POST", "/agents/support-bot/grants", {"tool": "no.such_tool"})
    check("a grant on an unknown tool -> 404", status == 404)

    print("live: a redeploy keeps API-made grants")
    lookup = {"name": "d12.lookup", "description": "builtin test", "risk_class": "read", "enabled": True,
              "taints_session": False, "args_schema": {"type": "object", "additionalProperties": False,
                                                       "properties": {"limit": {"type": "integer", "default": 1}}},
              "upstream": {"kind": "builtin", "handler": "query_customers"}}
    g.admin("POST", "/tools", lookup)
    g.admin("POST", "/agents/support-bot/grants", {"tool": "d12.lookup"})
    seed = HERE.parent.parent / "deploy" / "render" / "seed_fga.py"
    policy = HERE.parent.parent / "policy"
    if not seed.exists():
        seed, policy = Path("/srv/deploy/seed_fga.py"), Path("/srv/policy")
    import importlib.util
    if seed.exists() and os.environ.get("FGA_API_URL") and importlib.util.find_spec("yaml"):
        env = {**os.environ, "FGA_LOCAL_URL": os.environ["FGA_API_URL"], "POLICY_DIR": str(policy)}
        run = subprocess.run([sys.executable, str(seed)], env=env, capture_output=True, text=True, timeout=120)
        check("the boot-time seed sync runs", run.returncode == 0, run.stderr[-400:])
        check("  ... and reports the API's tuples", "api tuples=" in run.stderr, run.stderr[-300:])
        status, listed = g.admin("GET", "/agents/support-bot/grants")
        check("  ... every API-made grant is still in OpenFGA",
              {x["tool"] for x in listed} >= {"d12.echo", "d12.notify", "d12.wipe", "d12.lookup"}, listed)
        status, tok7 = g.mint("support-bot", ["d12.lookup"])
        status, body = g.call(tok7.get("access_token", ""), "d12.lookup", {})
        check("  ... and still works", status == 200, body)
        status, approvers = g.admin("GET", "/tools")
        check("  ... the API-made approver too", any(t["name"] == "d12.notify" and any(
            a["user"] == "user:shiwin" and a["source"] == "api" for a in t["approvers"] or []) for t in approvers))
    else:
        print("  (skipped: needs seed_fga.py, FGA_API_URL and PyYAML; check it on Render with eval/day12_check.py)")

    chain = g.http.get(f"{g.base}/audit/verify").json()
    check("audit chain still valid", chain.get("valid") is True, chain)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--unit-only", action="store_true")
    args = ap.parse_args()
    unit()
    if not args.unit_only:
        need = ("DATABASE_URL", "AGENTGATE_ORCHESTRATOR_KEY", "AGENTGATE_ADMIN_KEY", "UPSTREAM_MOCK_TOKEN")
        missing = [k for k in need if not os.environ.get(k)]
        if missing:
            print(f"setup: missing in the environment: {', '.join(missing)} (or pass --unit-only)")
            return 2
        asyncio.run(live())
    print(f"\n{COUNT - len(FAILED)}/{COUNT} checks passed" + (f"; FAILED: {', '.join(FAILED)}" if FAILED else ""))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
