"""Day 14: the MCP gateway. An MCP server at `/mcp` inside the broker.

Any MCP client (MCP Inspector, Claude Desktop through a bridge, an agent framework) connects to
`/mcp` and sees ONLY the tools its agent may use. Every `tools/call` goes through the same gate
as `POST /tools/{name}` (gate.run_gate), so it is judged by the same policy, writes the same audit
rows, taints the same sessions and escalates to the same Slack approvals.

Identity (decision 2026-11-17): the client sends its Auth0 machine-to-machine access token as the
bearer token on every request. The gateway verifies it with the Day 13 login check, maps the
Auth0 client to an agent, and itself mints a short-lived AgentGate token for that agent per MCP
session (re-minted before it expires). The client never holds an AgentGate token and the
gateway never forwards the Auth0 token anywhere.

What an agent sees:
  tools/list   the registry tools the agent may hold (the same rule as token issuance,
               decision.may_hold_scope). A tool it may not hold is not listed.
  tools/call   anything is accepted and judged by the gate. A call to a tool the agent was never
               shown is denied and audited like any other denied call.

Escalation (decision 2026-11-17): block and wait. The call stays open while a human decides in
Slack, with a progress notification about every 5 s, until the approval's TTL. Approve returns the
tool's result; deny or timeout returns an error result. If the client cancels or disconnects, the
approval is closed (counts as deny), so a late click can't run a call nobody is waiting for.

Protocol versions: only the handshake-era versions (with `Mcp-Session-Id`) are served. A request
for the newer sessionless version gets HTTP 400 / JSON-RPC -32022 listing what is supported, which
is how auto-negotiating clients fall back. Each MCP session maps to one AgentGate session, so
taint is tracked per MCP session (and follows the agent, see minting.mint).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

import anyio
import mcp_types as types
import msgspec
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.lowlevel.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS

from .approvals import agent_view
from .decision import may_hold_scope
from .fga import PolicyEngineError
from .gate import run_gate
from .minting import login_agent, mint
from .registry import MAX_BODY_BYTES, REGISTRY, Tool
from .tokens import AgentClaims, TokenError, decode_token

log = logging.getLogger("agentgate.mcp")

PROGRESS_EVERY_S = 5.0
POLL_EVERY_S = 1.0
RENEW_BEFORE_S = 60            # mint a fresh token when the current one has < 60 s left
MAX_WAITERS = 16               # calls blocked on a human at once, across all sessions
MAX_SCOPES = 64                # mint() takes at most 64
SESSION_IDLE_S = 900.0


@dataclass
class McpSession:
    """What the gateway keeps for one MCP session: the agent and its current AgentGate token."""
    agent_id: str
    token: str | None = None
    claims: AgentClaims | None = None
    scopes: tuple[str, ...] = ()
    last_used: float = field(default_factory=time.monotonic)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    agentgate_session: str | None = None    # keeps the same AgentGate session across re-mints


def _to_builtins(body: Any) -> Any:
    return msgspec.to_builtins(body)


def _annotations(tool: Tool) -> types.ToolAnnotations:
    """Hints for clients (not enforcement; the gate enforces). Derived from the registry row."""
    return types.ToolAnnotations(
        read_only_hint=tool.risk_class == "read",
        destructive_hint=tool.risk_class in ("destructive", "money"),
        open_world_hint=tool.risk_class == "egress" or tool.taints)


def _input_schema(tool: Tool) -> dict[str, Any]:
    schema = dict(tool.args_schema) if tool.args_schema else {}
    if schema.get("type") != "object":
        return {"type": "object"}
    return schema


def _error(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True)


def result_of(status: int, body: Any) -> types.CallToolResult:
    """Map the gate's (status, body) to an MCP tool result. 200 = the tool's result; everything
    else is an error result whose text is written by the broker (never copied from an upstream)."""
    data = _to_builtins(body)
    if status == 200:
        result = data.get("result") if isinstance(data, dict) else None
        text = json.dumps(result if result is not None else data, default=str)
        # An http or mcp upstream reports its own failure as {"ok": false, ...}: the call was
        # allowed and ran, but the tool failed, which MCP clients expect as an error result.
        failed = isinstance(result, dict) and result.get("ok") is False
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=failed,
                                    structured_content=result if isinstance(result, dict) else None)
    decision = data.get("decision", "deny") if isinstance(data, dict) else "deny"
    reason = (data.get("reason") if isinstance(data, dict) else None) or "refused"
    audit_id = data.get("audit_id") if isinstance(data, dict) else None
    where = f" (audit #{audit_id})" if audit_id else ""
    return _error(f"{decision}: {reason}{where}")


class McpGateway:
    def __init__(self) -> None:
        self.state: Any = None
        self.sessions: dict[tuple[str, str], McpSession] = {}
        self.waiters = asyncio.Semaphore(MAX_WAITERS)
        self.server = Server("agentgate", version="0.11.0",
                             instructions="AgentGate: tools are limited to what your agent may use. "
                                          "Risky calls wait for a human approval.",
                             on_list_tools=self._list_tools, on_call_tool=self._call_tool)
        self.manager = StreamableHTTPSessionManager(
            self.server, stateless=False, json_response=False, session_idle_timeout=SESSION_IDLE_S,
            max_sessions=200, max_request_body_size=MAX_BODY_BYTES)

    # ------------------------------------------------------------ lifecycle

    @contextlib.asynccontextmanager
    async def run(self, state: Any) -> AsyncIterator[None]:
        self.state = state
        async with self.manager.run():
            yield
        self.sessions.clear()

    # ------------------------------------------------------------ transport

    async def asgi(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        headers = {k.decode().lower(): v.decode("latin-1") for k, v in scope["headers"]}
        version = headers.get("mcp-protocol-version")
        if version is not None and version not in HANDSHAKE_PROTOCOL_VERSIONS:
            return await _respond(send, 400, {"jsonrpc": "2.0", "id": None, "error": {
                "code": -32022, "message": "unsupported protocol version",
                "data": {"supported": list(HANDSHAKE_PROTOCOL_VERSIONS), "requested": version[:32]}}})
        try:
            if int(headers.get("content-length") or 0) > MAX_BODY_BYTES:
                return await _respond(send, 413, {"error": "request too large"})
        except ValueError:
            return await _respond(send, 400, {"error": "bad Content-Length"})

        state = self.state
        async with state.pool.acquire() as conn:
            who, refused = await login_agent(state, conn, headers.get("authorization"), what="MCP login")
        if refused is not None:
            status, body = refused
            extra = [(b"www-authenticate", b'Bearer realm="agentgate"')] if status == 401 else []
            return await _respond(send, status, body, extra)
        agent_id, login = who
        # The SDK binds an MCP session to the identity that opened it: a session id stolen by
        # another client is refused (a different Auth0 client is a different `subject`).
        scope["user"] = AuthenticatedUser(AccessToken(
            token="-", client_id=agent_id, scopes=[], subject=login.client_id, claims={"agent_id": agent_id}))
        await self.manager.handle_request(scope, receive, send)

    # ------------------------------------------------------------ sessions and tokens

    def _session(self, ctx: Any) -> McpSession:
        request = ctx.request
        agent_id = request.scope["user"].access_token.client_id
        key = (agent_id, request.headers.get("mcp-session-id") or "-")
        now = time.monotonic()
        for k in [k for k, s in self.sessions.items() if now - s.last_used > SESSION_IDLE_S + 60]:
            del self.sessions[k]
        sess = self.sessions.get(key)
        if sess is None:
            sess = self.sessions[key] = McpSession(agent_id=agent_id)
        sess.last_used = now
        return sess

    async def _granted(self, conn: Any, agent_id: str) -> list[Tool]:
        """Tools this agent may hold: usable in the registry and reachable under the policy."""
        await REGISTRY.sync(conn)
        out: list[Tool] = []
        for t in sorted(REGISTRY.all(), key=lambda t: t.name):
            if t.usable and await may_hold_scope(self.state.fga, agent_id, t.name):
                out.append(t)
        return out[:MAX_SCOPES]

    async def _ensure_token(self, conn: Any, sess: McpSession, tools: list[Tool] | None = None
                            ) -> tuple[AgentClaims | None, tuple[int, Any] | None]:
        """A live AgentGate token for this MCP session. Mints one, or a fresh one before expiry."""
        async with sess.lock:
            names = tuple(t.name for t in tools) if tools is not None else sess.scopes
            fresh = (sess.claims is not None and sess.claims.expires_at - time.time() > RENEW_BEFORE_S
                     and (tools is None or names == sess.scopes))
            if fresh:
                return sess.claims, None
            if not names:
                names = tuple(t.name for t in await self._granted(conn, sess.agent_id))
            if not names:
                return None, (403, {"error": "no_tools", "reason": f"agent '{sess.agent_id}' may use no tools"})
            status, body = await mint(self.state, conn, agent_id=sess.agent_id, task="MCP session",
                                      scopes=list(names), session_id=sess.agentgate_session, login="auth0")
            if status != 201:
                return None, (status, body)
            sess.token, sess.scopes, sess.agentgate_session = body.access_token, names, body.session_id
            sess.claims = decode_token(self.state.key, self.state.settings, body.access_token)
            return sess.claims, None

    # ------------------------------------------------------------ MCP handlers

    async def _list_tools(self, ctx: Any, params: Any) -> types.ListToolsResult:
        sess = self._session(ctx)
        try:
            async with self.state.pool.acquire() as conn:
                tools = await self._granted(conn, sess.agent_id)
                if tools:
                    _, refused = await self._ensure_token(conn, sess, tools)
                    if refused is not None:
                        log.warning("MCP mint for %s refused: %s", sess.agent_id, refused[1])
                        tools = []
        except PolicyEngineError as exc:
            log.warning("MCP tools/list: policy engine unavailable: %s", exc)
            tools = []       # fail closed: show nothing
        return types.ListToolsResult(tools=[
            types.Tool(name=t.name, description=t.description or None, input_schema=_input_schema(t),
                       annotations=_annotations(t)) for t in tools])

    async def _call_tool(self, ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        sess = self._session(ctx)
        name, args = params.name, params.arguments or {}
        async with self.state.pool.acquire() as conn:
            claims, refused = await self._ensure_token(conn, sess)
            if refused is not None:
                status, body = refused
                return _error(f"deny: {body.get('reason', 'refused')}")
            status, body = await run_gate(self.state, conn, claims, name, args)
        if status == 202:
            status, body = await self._wait_for_human(ctx, claims, name, body)
        return result_of(status, body)

    async def _wait_for_human(self, ctx: Any, claims: AgentClaims, name: str, pending: Any) -> tuple[int, Any]:
        """Hold the call open until the approval resolves. Holds no database connection while
        waiting. Cancelled by the client = approval closed."""
        approvals = self.state.approvals
        approval_id = pending.approval_id
        import uuid
        aid = uuid.UUID(approval_id)
        if self.waiters.locked():
            await self._close_approval(aid)
            return 503, {"decision": "deny", "reason": "too many calls are waiting for approval; try again later",
                         "tool": name, "audit_id": pending.audit_id}
        async with self.waiters:
            started = time.monotonic()
            last_progress = 0.0
            ttl = float(self.state.settings.approval_ttl_seconds)
            try:
                while True:
                    async with self.state.pool.acquire() as conn:
                        row = await approvals.get(conn, aid)
                    if row is None:
                        return 404, {"decision": "deny", "reason": "unknown approval", "tool": name,
                                     "audit_id": pending.audit_id}
                    if row["status"] != "pending":
                        status, body = agent_view(row)
                        body["audit_id"] = pending.audit_id
                        return status, body
                    elapsed = time.monotonic() - started
                    if elapsed - last_progress >= PROGRESS_EVERY_S or last_progress == 0.0:
                        last_progress = elapsed
                        try:
                            await ctx.session.report_progress(
                                round(elapsed, 1), ttl, "waiting for a human to approve in Slack")
                        except Exception:      # noqa: BLE001 - a client that sent no progress token
                            log.debug("progress notification not sent", exc_info=True)
                    await asyncio.sleep(POLL_EVERY_S)
            except asyncio.CancelledError:
                await self._close_approval(aid)
                raise

    async def _close_approval(self, approval_id: Any) -> None:
        """Shielded: runs even while the surrounding task is being cancelled."""
        with anyio.CancelScope(shield=True):
            try:
                async with self.state.pool.acquire() as conn:
                    row = await self.state.approvals.get(conn, approval_id)
                    if row is not None:
                        await self.state.approvals.cancel(conn, row)
            except Exception:      # noqa: BLE001
                log.exception("could not close approval %s after the client left", approval_id)


async def _respond(send: Any, status: int, body: Any, extra: list[tuple[bytes, bytes]] | None = None) -> None:
    raw = json.dumps(body).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(raw)).encode()), *(extra or [])]})
    await send({"type": "http.response.body", "body": raw})


GATEWAY = McpGateway()
