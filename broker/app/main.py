"""AgentGate broker: the single enforcement point between agents and tools.

Run locally:  docker compose up broker
OpenAPI:      http://localhost:8000/schema/openapi.json   (Swagger UI at /schema/swagger)
"""

from __future__ import annotations

import hmac
import logging
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import asyncpg
import msgspec
from litestar import Litestar, Request, Response, get, post
from litestar.connection import ASGIConnection
from litestar.datastructures import State
from litestar.di import Provide
from litestar.exceptions import NotAuthorizedException, NotFoundException, PermissionDeniedException
from litestar.handlers.base import BaseRouteHandler
from litestar.openapi import OpenAPIConfig
from litestar.openapi.spec import Components, SecurityScheme

from . import audit
from .config import load_settings
from .db import create_pool
from .decision import decide, may_hold_scope
from .fga import FGAClient, PolicyEngineError
from .keys import SigningKey
from .tokens import TokenError, check_not_revoked, decode_token, issue_token
from .tools import TOOLS, amount_of, parse_args

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
    log.info("AgentGate up. kid=%s", app.state.key.kid)
    try:
        yield
    finally:
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


def _json(status: int, body: Any) -> Response:
    return Response(content=body, status_code=status)


# ---------------------------------------------------------------- public


@get("/health", tags=["meta"])
async def health(state: State) -> dict:
    return {"status": "ok", "openfga": await state.fga.ping()}


@get("/.well-known/jwks.json", tags=["tokens"])
async def jwks(state: State) -> dict:
    """Public key set, so anyone can verify AgentGate tokens offline."""
    return state.key.jwks()


@get("/audit/verify", tags=["audit"], dependencies={"conn": Provide(provide_conn)})
async def audit_verify(conn: asyncpg.Connection) -> dict:
    """Recompute the hash chain and report the first broken row."""
    return await audit.verify_chain(conn)


# ---------------------------------------------------------------- tokens


@post("/tokens", tags=["tokens"], guards=[orchestrator_guard], status_code=201,
      dependencies={"conn": Provide(provide_conn)}, security=[{"OrchestratorKey": []}])
async def create_token(data: TokenRequest, state: State, conn: asyncpg.Connection) -> Response[TokenResponse]:
    """Mint a 10-minute, task-scoped token for one agent."""
    settings, fga = state.settings, state.fga
    scopes = sorted(set(data.scopes))

    async def refuse(status: int, reason: str, session_id: str | None = None) -> Response:
        ev = await audit.append_event(conn, event_type="token_denied", decision="deny", reason=reason,
                                      agent_id=data.agent_id, session_id=session_id)
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

    # Session: reuse the orchestrator run's session, or start a new one.
    if data.session_id:
        try:
            sid = uuid.UUID(data.session_id)
        except ValueError:
            return await refuse(400, "session_id is not a UUID")
        if not await conn.fetchval("SELECT 1 FROM sessions WHERE id = $1", sid):
            return await refuse(404, "unknown session_id")
    else:
        sid = uuid.uuid4()
        await conn.execute("INSERT INTO sessions (id) VALUES ($1)", sid)

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
                             agent_id=data.agent_id, session_id=str(sid), task_id=task_id, jti=claims["jti"])
    body = TokenResponse(
        access_token=token, token_type="Bearer", expires_in=settings.token_ttl_seconds,
        expires_at=datetime.fromtimestamp(claims["exp"], tz=timezone.utc).isoformat(),
        agent_id=data.agent_id, session_id=str(sid), task_id=task_id, jti=claims["jti"], scopes=scopes,
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

    # 2. Revocation / kill switch. The token is genuine, so this attempt is audited.
    try:
        await check_not_revoked(conn, claims)
    except TokenError as exc:
        ev = await audit.append_event(conn, event_type="tool_call", decision="deny", reason=str(exc),
                                      agent_id=claims.agent_id, session_id=claims.session_id,
                                      task_id=claims.task_id, jti=claims.jti, tool=name)
        return _json(401, {"decision": "deny", "reason": str(exc), "tool": name, "audit_id": ev["id"]})

    async def record(decision: str, reason: str, *, args_hash: str | None = None,
                     tainted: bool | None = None) -> dict:
        return await audit.append_event(
            conn, event_type="tool_call", decision=decision, reason=reason, agent_id=claims.agent_id,
            session_id=claims.session_id, task_id=claims.task_id, jti=claims.jti, tool=name,
            args_hash=args_hash, session_tainted=tainted)

    # 3. Known tool, valid arguments.
    tool = TOOLS.get(name)
    if tool is None:
        ev = await record("deny", f"unknown tool '{name}'")
        return _json(404, ToolResult(decision="deny", reason=f"unknown tool '{name}'", tool=name,
                                     audit_id=ev["id"]))
    args_hash = audit.args_digest(settings.args_hmac_key, data.args)
    try:
        parsed = parse_args(tool, data.args)
    except msgspec.ValidationError as exc:
        ev = await record("deny", f"invalid arguments: {exc}", args_hash=args_hash)
        return _json(422, ToolResult(decision="deny", reason=f"invalid arguments: {exc}", tool=name,
                                     audit_id=ev["id"]))

    # 4. Session taint: set by the gate, never by the agent.
    tainted = await conn.fetchval("SELECT tainted FROM sessions WHERE id = $1::uuid", claims.session_id)
    if tainted is None:
        ev = await record("deny", "unknown session", args_hash=args_hash)
        return _json(401, ToolResult(decision="deny", reason="unknown session", tool=name, audit_id=ev["id"]))

    # 5. Policy decision.
    decision = await decide(state.fga, agent_id=claims.agent_id, tool=name, token_scopes=claims.scopes,
                            amount=amount_of(tool, parsed), session_tainted=tainted)

    if decision.outcome == "deny":
        ev = await record("deny", decision.reason, args_hash=args_hash, tainted=tainted)
        return _json(503 if decision.policy_error else 403,
                     ToolResult(decision="deny", reason=decision.reason, tool=name, audit_id=ev["id"],
                                session_tainted=tainted))

    if decision.outcome == "escalate":
        approval_id = uuid.uuid4()
        await conn.execute(
            """INSERT INTO approvals (id, agent_id, session_id, task_id, tool, args, args_hash, reason)
               VALUES ($1, $2, $3::uuid, $4::uuid, $5, $6, $7, $8)""",
            approval_id, claims.agent_id, claims.session_id, claims.task_id, name, data.args,
            args_hash, decision.reason)
        # TODO(Day 4): post Approve / Deny buttons to Slack; GET /approvals/{id} for agent polling.
        ev = await record("escalate", f"{decision.reason}; approval {approval_id}", args_hash=args_hash,
                          tainted=tainted)
        return _json(202, ToolResult(decision="escalate", reason=decision.reason, tool=name,
                                     audit_id=ev["id"], approval_id=str(approval_id), status="pending",
                                     session_tainted=tainted))

    # 6. Allow: run the tool (the broker, not the agent, holds any real API keys).
    try:
        result = await tool.run(parsed)
    except ValueError as exc:
        ev = await record("allow", f"{decision.reason}; tool rejected input: {exc}", args_hash=args_hash,
                          tainted=tainted)
        return _json(400, ToolResult(decision="allow", reason=f"tool error: {exc}", tool=name,
                                     audit_id=ev["id"], session_tainted=tainted))
    # TODO(Day 5): if tool.taints, set sessions.tainted = true (tainted_by = name) here.
    ev = await record("allow", decision.reason, args_hash=args_hash, tainted=tainted)
    return _json(200, ToolResult(decision="allow", reason=decision.reason, tool=name, audit_id=ev["id"],
                                 result=result, session_tainted=tainted))


# ---------------------------------------------------------------- app

openapi_config = OpenAPIConfig(
    title="AgentGate",
    version="0.2.0",
    description="Identity and permissions broker for AI agents.",
    components=Components(security_schemes={
        "BearerAuth": SecurityScheme(type="http", scheme="bearer", bearer_format="JWT"),
        "AdminKey": SecurityScheme(type="apiKey", name="X-Admin-Key", security_scheme_in="header"),
        "OrchestratorKey": SecurityScheme(type="apiKey", name="X-Orchestrator-Key", security_scheme_in="header"),
    }),
)

app = Litestar(
    route_handlers=[health, jwks, audit_verify, create_token, revoke_token, list_agents,
                    disable_agent, enable_agent, call_tool],
    lifespan=[lifespan],
    openapi_config=openapi_config,
)
