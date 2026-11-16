"""AgentGate broker: the single enforcement point between agents and tools.

Run locally:  docker compose up broker
OpenAPI:      http://localhost:8000/schema/openapi.json   (Swagger UI at /schema/swagger)
"""

from __future__ import annotations

import hmac
import logging
import re
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import asyncpg
import msgspec
from litestar import Litestar, Request, Response, asgi, get, post
from litestar.connection import ASGIConnection
from litestar.datastructures import State
from litestar.di import Provide
from litestar.exceptions import NotAuthorizedException, NotFoundException
from litestar.handlers.base import BaseRouteHandler
from litestar.openapi import OpenAPIConfig
from litestar.openapi.spec import Components, SecurityScheme

from . import audit, taint
from .approvals import ApprovalError, ApprovalService, Approver, admin_view, agent_view
from .config import load_settings
from .db import create_pool
from .decision import decide, may_hold_scope
from .fga import FGAClient, PolicyEngineError
from .keys import SigningKey
from .slack import SLACK_EVENTS_PATH, SlackApprovals
from .tokens import TokenError, check_not_revoked, decode_token, issue_token
from .tools import TOOLS, amount_of, host_of, parse_args, recipient_domain_of

log = logging.getLogger("agentgate")

# ---------------------------------------------------------------- lifespan


@asynccontextmanager
async def lifespan(app: Litestar) -> AsyncGenerator[None, None]:
    settings = load_settings()
    app.state.settings = settings
    app.state.key = SigningKey(settings.signing_key_b64)
    app.state.pool = await create_pool(settings.database_url)
    app.state.fga = FGAClient(settings.fga_api_url, settings.fga_store_id, settings.fga_model_id)
    if not await app.state.fga.ping():
        log.warning("OpenFGA store %s not reachable at startup; calls will fail closed", settings.fga_store_id)

    # Day 4: approvals + Slack. Slack is optional: without it, approvals are decided via the admin API.
    approvals = ApprovalService(app.state.pool, app.state.fga, ttl_seconds=settings.approval_ttl_seconds)
    app.state.approvals = approvals
    app.state.slack = None
    if settings.slack_mode != "off":
        app.state.slack = SlackApprovals(settings, approvals.decide)
        approvals.notifier = app.state.slack
        await app.state.slack.start()
    async with app.state.pool.acquire() as conn:
        swept = await approvals.expire_overdue(conn)   # approvals left pending by a restart
    log.info("AgentGate up. kid=%s slack=%s expired_on_boot=%d", app.state.key.kid, settings.slack_mode, swept)
    try:
        yield
    finally:
        if app.state.slack is not None:
            await app.state.slack.stop()
        await app.state.fga.close()
        await app.state.pool.close()


async def provide_conn(state: State) -> AsyncGenerator[asyncpg.Connection, None]:
    async with state.pool.acquire() as conn:
        yield conn


# ---------------------------------------------------------------- guards


def _key_guard(header: str, setting: str):
    def guard(connection: ASGIConnection, _: BaseRouteHandler) -> None:
        supplied = connection.headers.get(header, "")
        expected = getattr(connection.app.state.settings, setting)
        if not supplied or not hmac.compare_digest(supplied, expected):
            raise NotAuthorizedException(f"missing or wrong {header}")
    return guard


admin_guard = _key_guard("x-admin-key", "admin_api_key")             # TODO(Day 6): Auth0 login
orchestrator_guard = _key_guard("x-orchestrator-key", "orchestrator_api_key")

# ---------------------------------------------------------------- schemas


class TokenRequest(msgspec.Struct, forbid_unknown_fields=True):
    agent_id: str
    task: str
    scopes: list[str]
    session_id: str | None = None   # omit to start a new session (a new orchestrator run)


class TokenResponse(msgspec.Struct):
    access_token: str
    token_type: str
    expires_in: int
    expires_at: str
    agent_id: str
    session_id: str
    task_id: str
    jti: str
    scopes: list[str]
    session_tainted: bool = False     # Day 5: a reused session keeps its taint
    tainted_by: str | None = None


class RevokeTokenRequest(msgspec.Struct, forbid_unknown_fields=True):
    jti: str
    reason: str = "revoked by admin"


class KillSwitchRequest(msgspec.Struct, forbid_unknown_fields=True):
    reason: str = "kill switch"


class ToolCall(msgspec.Struct, forbid_unknown_fields=True):
    args: dict[str, Any] = {}


class ToolResult(msgspec.Struct, omit_defaults=True):
    decision: str                    # 'allow' | 'escalate' | 'deny'
    reason: str
    tool: str
    audit_id: int
    session_tainted: bool | None = None
    result: dict[str, Any] | None = None
    approval_id: str | None = None   # escalate only
    status: str | None = None        # escalate: 'pending'
    expires_at: str | None = None    # escalate: when the approval times out (counts as deny)


def _json(status: int, body: Any) -> Response:
    return Response(content=body, status_code=status)


# ---------------------------------------------------------------- public


@get("/health", tags=["meta"])
async def health(state: State) -> dict:
    return {"status": "ok", "openfga": await state.fga.ping(), "slack": state.settings.slack_mode}


@get("/.well-known/jwks.json", tags=["tokens"])
async def jwks(state: State) -> dict:
    """Public key set, so anyone can verify AgentGate tokens offline."""
    return state.key.jwks()


@get("/audit/verify", tags=["audit"], dependencies={"conn": Provide(provide_conn)})
async def audit_verify(conn: asyncpg.Connection) -> dict:
    """Recompute the hash chain and report the first broken row."""
    return await audit.verify_chain(conn)


@get("/audit/checkpoint", tags=["audit"], dependencies={"conn": Provide(provide_conn)})
async def audit_checkpoint(state: State, conn: asyncpg.Connection) -> dict:
    """Day 8: the chain head (last id + hash), signed by the broker. Public, like /audit/verify:
    it is meant to be copied somewhere outside the database (scripts/anchor.py)."""
    return await audit.checkpoint(conn, state.key, state.settings.issuer)


@get("/audit/hashes", tags=["audit"], dependencies={"conn": Provide(provide_conn)})
async def audit_hashes(conn: asyncpg.Connection, ids: str) -> Response:
    """Day 8: stored hashes for ?ids=1,5,9 (at most 500), to compare against published anchors.
    A row hash reveals nothing about the row; the head hash is already public in /audit/verify."""
    try:
        wanted = sorted({int(x) for x in ids.split(",") if x.strip()})
    except ValueError:
        return _json(400, {"error": "ids must be comma-separated integers"})
    if not wanted or len(wanted) > 500 or wanted[0] < 1 or wanted[-1] > 2**62:
        return _json(400, {"error": "give 1 to 500 positive ids"})
    return _json(200, {"hashes": await audit.hashes_at(conn, wanted)})


@get("/audit/events", tags=["audit"], guards=[admin_guard], dependencies={"conn": Provide(provide_conn)},
     security=[{"AdminKey": []}])
async def audit_events(conn: asyncpg.Connection, session_id: str | None = None, limit: int = 50) -> list[dict]:
    """Recent audit events, newest first; filter to one session with ?session_id=.
    Every session-bound event carries session_tainted (Day 5). Args are HMACs only."""
    limit = min(max(limit, 1), 500)
    cols = ("id, ts, event_type, agent_id, session_id, tool, decision, reason, approver, "
            "session_tainted, args_hash, hash")
    if session_id:
        rows = await conn.fetch(f"SELECT {cols} FROM audit_events WHERE session_id = $1 ORDER BY id DESC LIMIT $2",
                                session_id, limit)
    else:
        rows = await conn.fetch(f"SELECT {cols} FROM audit_events ORDER BY id DESC LIMIT $1", limit)
    return [dict(r) for r in rows]


# ---------------------------------------------------------------- tokens


@post("/tokens", tags=["tokens"], guards=[orchestrator_guard], status_code=201,
      dependencies={"conn": Provide(provide_conn)}, security=[{"OrchestratorKey": []}])
async def create_token(data: TokenRequest, state: State, conn: asyncpg.Connection) -> Response[TokenResponse]:
    """Mint a 10-minute, task-scoped token for one agent."""
    settings, fga = state.settings, state.fga
    scopes = sorted(set(data.scopes))

    async def refuse(status: int, reason: str) -> Response:
        # Day 5: if the request names an existing session, the denial carries its taint too.
        st = await taint.load(conn, data.session_id) if data.session_id else None
        ev = await audit.append_event(conn, event_type="token_denied", decision="deny", reason=reason,
                                      agent_id=data.agent_id, session_id=data.session_id,
                                      session_tainted=st.tainted if st else None)
        return _json(status, {"error": "token_denied", "reason": reason, "audit_id": ev["id"]})

    agent = await conn.fetchrow("SELECT id, status FROM agents WHERE id = $1", data.agent_id)
    if agent is None:
        return await refuse(404, f"unknown agent '{data.agent_id}'")
    if agent["status"] != "active":
        return await refuse(403, f"agent '{data.agent_id}' is disabled (kill switch)")
    if not scopes:
        return await refuse(400, "request at least one scope")
    unknown = [s for s in scopes if s not in TOOLS]
    if unknown:
        return await refuse(400, f"unknown tool scope(s): {', '.join(unknown)}")

    try:
        not_granted = [s for s in scopes if not await may_hold_scope(fga, data.agent_id, s)]
    except PolicyEngineError as exc:
        return await refuse(503, f"policy engine unavailable, failing closed: {exc}")
    if not_granted:
        return await refuse(403, f"agent '{data.agent_id}' may not hold: {', '.join(not_granted)}")

    # Session: reuse the orchestrator run's session (taint and all), or start a new, clean one.
    if data.session_id:
        try:
            sid = uuid.UUID(data.session_id)
        except ValueError:
            return await refuse(400, "session_id is not a UUID")
        st = await taint.load(conn, str(sid))
        if st is None:
            return await refuse(404, "unknown session_id")
    else:
        sid = uuid.uuid4()
        await conn.execute("INSERT INTO sessions (id) VALUES ($1)", sid)
        st = taint.SessionTaint(False)

    task_id = str(uuid.uuid4())
    token, claims = issue_token(state.key, settings, agent_id=data.agent_id, session_id=str(sid),
                                task_id=task_id, scopes=scopes)
    await conn.execute(
        """INSERT INTO tokens (jti, agent_id, session_id, task_id, task, scopes, issued_at, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7), to_timestamp($8))""",
        uuid.UUID(claims["jti"]), data.agent_id, sid, uuid.UUID(task_id), data.task, scopes,
        claims["iat"], claims["exp"],
    )
    await audit.append_event(conn, event_type="token_issued", decision="info",
                             reason=f"scopes: {' '.join(scopes)}; task: {data.task[:120]}",
                             agent_id=data.agent_id, session_id=str(sid), task_id=task_id, jti=claims["jti"],
                             session_tainted=st.tainted)
    body = TokenResponse(
        access_token=token, token_type="Bearer", expires_in=settings.token_ttl_seconds,
        expires_at=datetime.fromtimestamp(claims["exp"], tz=timezone.utc).isoformat(),
        agent_id=data.agent_id, session_id=str(sid), task_id=task_id, jti=claims["jti"], scopes=scopes,
        session_tainted=st.tainted, tainted_by=st.tainted_by,
    )
    return _json(201, body)


@post("/tokens/revoke", tags=["tokens"], guards=[admin_guard], status_code=200,
      dependencies={"conn": Provide(provide_conn)}, security=[{"AdminKey": []}])
async def revoke_token(data: RevokeTokenRequest, conn: asyncpg.Connection) -> dict:
    try:
        jti = uuid.UUID(data.jti)
    except ValueError as exc:
        raise NotFoundException("jti is not a UUID") from exc
    agent_id = await conn.fetchval("SELECT agent_id FROM tokens WHERE jti = $1", jti)
    if agent_id is None:
        raise NotFoundException("unknown jti")
    await conn.execute("INSERT INTO revocations (jti, reason) VALUES ($1, $2)", jti, data.reason)
    ev = await audit.append_event(conn, event_type="token_revoked", decision="info", reason=data.reason,
                                  agent_id=agent_id, jti=str(jti))
    return {"revoked": str(jti), "audit_id": ev["id"]}


# ---------------------------------------------------------------- agents / kill switch


@get("/agents", tags=["agents"], guards=[admin_guard], dependencies={"conn": Provide(provide_conn)},
     security=[{"AdminKey": []}])
async def list_agents(conn: asyncpg.Connection) -> list[dict]:
    rows = await conn.fetch("SELECT id, owner, display_name, status FROM agents ORDER BY id")
    return [dict(r) for r in rows]


@post("/agents/{agent_id:str}/disable", tags=["agents"], guards=[admin_guard], status_code=200,
      dependencies={"conn": Provide(provide_conn)}, security=[{"AdminKey": []}])
async def disable_agent(agent_id: str, data: KillSwitchRequest, conn: asyncpg.Connection) -> dict:
    """Kill switch: every existing token for this agent stops working at once,
    and no new ones are issued until it is re-enabled."""
    async with conn.transaction():
        updated = await conn.fetchval(
            "UPDATE agents SET status = 'disabled' WHERE id = $1 RETURNING id", agent_id)
        if updated is None:
            raise NotFoundException(f"unknown agent '{agent_id}'")
        await conn.execute("INSERT INTO revocations (agent_id, reason) VALUES ($1, $2)", agent_id, data.reason)
    ev = await audit.append_event(conn, event_type="agent_disabled", decision="info", reason=data.reason,
                                  agent_id=agent_id)
    return {"agent_id": agent_id, "status": "disabled", "audit_id": ev["id"]}


@post("/agents/{agent_id:str}/enable", tags=["agents"], guards=[admin_guard], status_code=200,
      dependencies={"conn": Provide(provide_conn)}, security=[{"AdminKey": []}])
async def enable_agent(agent_id: str, conn: asyncpg.Connection) -> dict:
    """Re-enable after a kill switch. Old tokens stay revoked; the agent needs new ones."""
    updated = await conn.fetchval("UPDATE agents SET status = 'active' WHERE id = $1 RETURNING id", agent_id)
    if updated is None:
        raise NotFoundException(f"unknown agent '{agent_id}'")
    ev = await audit.append_event(conn, event_type="agent_enabled", decision="info",
                                  reason="re-enabled by admin", agent_id=agent_id)
    return {"agent_id": agent_id, "status": "active", "audit_id": ev["id"]}


# ---------------------------------------------------------------- tool gateway


@post("/tools/{name:str}", tags=["tools"], status_code=200, dependencies={"conn": Provide(provide_conn)},
      security=[{"BearerAuth": []}])
async def call_tool(name: str, data: ToolCall, request: Request, state: State,
                    conn: asyncpg.Connection) -> Response[ToolResult]:
    """Every agent tool call goes through here.
    200 = allow (result included), 202 = escalate (pending human), 403 = deny."""
    settings = state.settings

    # 1. Authenticate: signature, expiry, issuer, audience.
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return _json(401, {"decision": "deny", "reason": "missing bearer token"})
    try:
        claims = decode_token(state.key, settings, auth[7:].strip())
    except TokenError as exc:
        return _json(401, {"decision": "deny", "reason": str(exc)})

    # 2. Session taint (Day 5): set by the gate, never by the agent. Loaded first so that
    #    every audit row for this call, even an early deny, records the taint it was judged under.
    st = await taint.load(conn, claims.session_id)
    tainted = st.tainted if st else None

    async def record(decision: str, reason: str, *, args_hash: str | None = None) -> dict:
        return await audit.append_event(
            conn, event_type="tool_call", decision=decision, reason=reason, agent_id=claims.agent_id,
            session_id=claims.session_id, task_id=claims.task_id, jti=claims.jti, tool=name,
            args_hash=args_hash, session_tainted=tainted)

    # 3. Revocation / kill switch. The token is genuine, so this attempt is audited.
    try:
        await check_not_revoked(conn, claims)
    except TokenError as exc:
        ev = await record("deny", str(exc))
        return _json(401, {"decision": "deny", "reason": str(exc), "tool": name, "audit_id": ev["id"],
                           "session_tainted": tainted})

    # 4. Known session, known tool, valid arguments.
    if st is None:
        ev = await record("deny", "unknown session")
        return _json(401, ToolResult(decision="deny", reason="unknown session", tool=name, audit_id=ev["id"]))
    tool = TOOLS.get(name)
    if tool is None:
        ev = await record("deny", f"unknown tool '{name}'")
        return _json(404, ToolResult(decision="deny", reason=f"unknown tool '{name}'", tool=name,
                                     audit_id=ev["id"], session_tainted=tainted))
    args_hash = audit.args_digest(settings.args_hmac_key, data.args)
    try:
        parsed = parse_args(tool, data.args)
    except msgspec.ValidationError as exc:
        ev = await record("deny", f"invalid arguments: {exc}", args_hash=args_hash)
        return _json(422, ToolResult(decision="deny", reason=f"invalid arguments: {exc}", tool=name,
                                     audit_id=ev["id"], session_tainted=tainted))

    # 5. Policy decision, with the session's taint as OpenFGA context.
    decision = await decide(state.fga, agent_id=claims.agent_id, tool=name, token_scopes=claims.scopes,
                            amount=amount_of(tool, parsed), session_tainted=st.tainted,
                            tainted_by=st.tainted_by, host=host_of(tool, parsed),
                            recipient_domain=recipient_domain_of(tool, parsed),
                            has_recipient=bool(tool.recipient_field))

    if decision.outcome == "deny":
        ev = await record("deny", decision.reason, args_hash=args_hash)
        return _json(503 if decision.policy_error else 403,
                     ToolResult(decision="deny", reason=decision.reason, tool=name, audit_id=ev["id"],
                                session_tainted=tainted))

    if decision.outcome == "escalate":
        # Raw args are kept on the approval row only while pending: the broker replays the
        # call itself on Approve, so the agent never re-sends it.
        row = await state.approvals.create(
            conn, agent_id=claims.agent_id, session_id=claims.session_id, task_id=claims.task_id,
            tool=name, args=data.args, args_hash=args_hash, reason=decision.reason, session_tainted=tainted)
        ev = await record("escalate", f"{decision.reason}; approval {row['id']}", args_hash=args_hash)
        await state.approvals.announce(conn, row, ev["id"])
        return _json(202, ToolResult(decision="escalate", reason=decision.reason, tool=name,
                                     audit_id=ev["id"], approval_id=str(row["id"]), status="pending",
                                     expires_at=row["expires_at"].isoformat(), session_tainted=tainted))

    # 6. Allow: run the tool (the broker, not the agent, holds any real API keys).
    try:
        result = await tool.run(parsed)
    except ValueError as exc:
        ev = await record("allow", f"{decision.reason}; tool rejected input: {exc}", args_hash=args_hash)
        return _json(400, ToolResult(decision="allow", reason=f"tool error: {exc}", tool=name,
                                     audit_id=ev["id"], session_tainted=tainted))
    # The call row records the taint the decision was made under (before this call).
    ev = await record("allow", decision.reason, args_hash=args_hash)

    # 7. Day 5: untrusted content taints the session BEFORE the agent sees it. If marking
    #    fails, this raises and the content is never returned (fail closed).
    if tool.taints:
        await taint.mark(conn, session_id=claims.session_id, tool=name, agent_id=claims.agent_id,
                         task_id=claims.task_id, jti=claims.jti)
        tainted = True
    # Response: session_tainted is the session's state AFTER this call.
    return _json(200, ToolResult(decision="allow", reason=decision.reason, tool=name, audit_id=ev["id"],
                                 result=result, session_tainted=tainted))


# ---------------------------------------------------------------- approvals (Day 4)


async def _agent_claims(request: Request, state: State, conn: asyncpg.Connection):
    """Bearer auth for agent-facing approval endpoints: same checks as the tool gateway
    (signature, expiry, revocation / kill switch). Returns (claims, None) or (None, error response)."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None, _json(401, {"decision": "deny", "reason": "missing bearer token"})
    try:
        claims = decode_token(state.key, state.settings, auth[7:].strip())
        await check_not_revoked(conn, claims)
    except TokenError as exc:
        return None, _json(401, {"decision": "deny", "reason": str(exc)})
    return claims, None


async def _own_approval(conn: asyncpg.Connection, state: State, approval_id: uuid.UUID, claims) -> dict | None:
    """An agent may only see approvals from its own agent id AND session."""
    row = await state.approvals.get(conn, approval_id)
    if row is None or row["agent_id"] != claims.agent_id or str(row["session_id"]) != claims.session_id:
        return None
    return row


@get("/approvals/{approval_id:uuid}", tags=["approvals"], dependencies={"conn": Provide(provide_conn)},
     security=[{"BearerAuth": []}])
async def poll_approval(approval_id: uuid.UUID, request: Request, state: State,
                        conn: asyncpg.Connection) -> Response:
    """Agent polling (every 2 s). 202 = still pending, 200 = approved (tool result included),
    403 = denied or expired (timeout counts as deny). Not audited per poll; the resolution is."""
    claims, err = await _agent_claims(request, state, conn)
    if err is not None:
        return err
    row = await _own_approval(conn, state, approval_id, claims)
    if row is None:
        return _json(404, {"decision": "deny", "reason": "unknown approval"})
    status, body = agent_view(row)
    return _json(status, body)


@post("/approvals/{approval_id:uuid}/cancel", tags=["approvals"], status_code=200,
      dependencies={"conn": Provide(provide_conn)}, security=[{"BearerAuth": []}])
async def cancel_approval(approval_id: uuid.UUID, request: Request, state: State,
                          conn: asyncpg.Connection) -> Response:
    """The agent stopped waiting. Closes the approval so a late click can't run the call.
    If a human already decided, returns that decision instead."""
    claims, err = await _agent_claims(request, state, conn)
    if err is not None:
        return err
    row = await _own_approval(conn, state, approval_id, claims)
    if row is None:
        return _json(404, {"decision": "deny", "reason": "unknown approval"})
    status, body = agent_view(await state.approvals.cancel(conn, row))
    return _json(status, body)


class DecisionRequest(msgspec.Struct, forbid_unknown_fields=True):
    approve: bool
    approver: str      # AgentGate user name, e.g. 'shiwin'; must be an OpenFGA approver of the tool
    # Day 8: where the click came from, for the audit log: 'admin-ui:<Auth0 sub>'. Optional;
    # without it the decision is recorded as 'admin-api' (curl, scripts/decide.ps1).
    via: str | None = None


# The admin key holder may only label a decision as coming from the admin UI, never as
# 'slack:...' or 'timeout'. Auth0 subs look like 'auth0|64f0...' or 'google-oauth2|1234'.
_VIA = re.compile(r"admin-ui:[A-Za-z0-9|._@-]{1,100}")


@get("/approvals", tags=["approvals"], guards=[admin_guard], dependencies={"conn": Provide(provide_conn)},
     security=[{"AdminKey": []}])
async def list_approvals(state: State, conn: asyncpg.Connection, status: str | None = "pending",
                         limit: int = 50) -> list[dict]:
    """Approvals queue (Day 6 UI). status: pending | approved | denied | expired | all."""
    rows = await state.approvals.list_recent(conn, None if status == "all" else status, min(max(limit, 1), 200))
    return [admin_view(r) for r in rows]


@post("/approvals/{approval_id:uuid}/decision", tags=["approvals"], guards=[admin_guard], status_code=200,
      security=[{"AdminKey": []}])
async def decide_approval(approval_id: uuid.UUID, data: DecisionRequest, state: State) -> Response:
    """Fallback (and Day 6 UI) path for Approve / Deny, same rules as the Slack buttons."""
    # The UI's server route takes `approver` and `via` from the Auth0 session, never from the browser.
    if data.via is not None and not _VIA.fullmatch(data.via):
        return _json(400, {"error": "approval_not_applied", "reason": "via must look like 'admin-ui:<Auth0 sub>'"})
    try:
        row = await state.approvals.decide(approval_id, approve=data.approve,
                                           approver=Approver(user=data.approver.removeprefix("user:"),
                                                             via=data.via or "admin-api"))
    except ApprovalError as exc:
        return _json(exc.status, {"error": "approval_not_applied", "reason": str(exc)})
    return _json(200, admin_view(row))


@asgi(SLACK_EVENTS_PATH, include_in_schema=False)
async def slack_events(scope: dict, receive: Any, send: Any) -> None:
    """Slack HTTP mode: button clicks arrive here. Bolt checks the signing secret."""
    slack = scope["litestar_app"].state.slack
    if slack is None or slack.settings.slack_mode != "http":
        await send({"type": "http.response.start", "status": 404,
                    "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"Slack HTTP mode is not enabled"})
        return
    await slack.http_handler(scope, receive, send)


# ---------------------------------------------------------------- app

openapi_config = OpenAPIConfig(
    title="AgentGate",
    version="0.5.0",
    description="Identity and permissions broker for AI agents.",
    components=Components(security_schemes={
        "BearerAuth": SecurityScheme(type="http", scheme="bearer", bearer_format="JWT"),
        "AdminKey": SecurityScheme(type="apiKey", name="X-Admin-Key", security_scheme_in="header"),
        "OrchestratorKey": SecurityScheme(type="apiKey", name="X-Orchestrator-Key", security_scheme_in="header"),
    }),
)

app = Litestar(
    route_handlers=[health, jwks, audit_verify, audit_checkpoint, audit_hashes, audit_events, create_token, revoke_token, list_agents,
                    disable_agent, enable_agent, call_tool,
                    poll_approval, cancel_approval, list_approvals, decide_approval, slack_events],
    lifespan=[lifespan],
    openapi_config=openapi_config,
)
