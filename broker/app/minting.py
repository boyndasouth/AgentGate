"""Minting AgentGate tokens, and checking an agent's own login.

Moved out of main.py on Day 14 so the MCP gateway (mcp_gateway.py) can use the same two steps as
the HTTP routes, without importing main:

    mint(...)         what POST /tokens and POST /tokens/agent do after they know WHO is asking:
                      the scope, registry and kill-switch checks, the session, the token row,
                      the audit rows. Returns (http status, body).
    login_agent(...)  Day 13's check of an Auth0 bearer token and its mapping to an agent. Returns
                      the agent id, or the refusal (status, body) already audited as before.

Nothing about the rules changed in the move.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import asyncpg
import msgspec
from litestar.datastructures import State

from . import agent_login, audit, taint
from .agent_login import Forged, Login, Rejected, Unavailable
from .decision import may_hold_scope
from .fga import PolicyEngineError
from .registry import REGISTRY
from .tokens import issue_token

log = logging.getLogger("agentgate")


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
    principal: str | None = None      # Day 10, exchanged tokens: whose access this token uses
    actors: list[str] | None = None   # Day 10: calling agent first, then earlier hops
    delegation_ids: list[str] | None = None
    login: str | None = None          # Day 13: 'auth0' when the agent logged in as itself


async def mint(state: State, conn: asyncpg.Connection, *, agent_id: str, task: str, scopes: list[str],
               session_id: str | None, login: str | None) -> tuple[int, Any]:
    """Shared by POST /tokens (the orchestrator names the agent), POST /tokens/agent (Day 13: the
    agent proved who it is, `login` = 'auth0') and the MCP gateway (Day 14, also 'auth0'). Same
    scope and registry checks for all of them."""
    settings, fga = state.settings, state.fga
    scopes = sorted(set(scopes))

    async def refuse(status: int, reason: str) -> tuple[int, Any]:
        # Day 5: if the request names an existing session, the denial carries its taint too.
        st = await taint.load(conn, session_id) if session_id else None
        ev = await audit.append_event(conn, event_type="token_denied", decision="deny", reason=reason,
                                      agent_id=agent_id, session_id=session_id,
                                      session_tainted=st.tainted if st else None)
        return status, {"error": "token_denied", "reason": reason, "audit_id": ev["id"]}

    agent = await conn.fetchrow("SELECT id, status, owner, auth0_client_id FROM agents WHERE id = $1", agent_id)
    if agent is None:
        return await refuse(404, f"unknown agent '{agent_id}'")
    if agent["status"] != "active":
        return await refuse(403, f"agent '{agent_id}' is disabled (kill switch)")
    if login is None and agent["auth0_client_id"]:
        # Day 13: once an agent has its own login, nobody else can speak for it.
        return await refuse(403, f"agent '{agent_id}' logs in as itself (POST /tokens/agent); "
                                 "the orchestrator key can't mint its tokens")
    if not scopes:
        return await refuse(400, "request at least one scope")
    if len(scopes) > 64 or len(task) > 2000:
        return await refuse(400, "too many scopes or a task description over 2000 characters")
    await REGISTRY.sync(conn)
    unknown = [s for s in scopes if REGISTRY.peek(s) is None]
    if unknown:
        return await refuse(400, f"unknown tool scope(s): {', '.join(u[:64] for u in unknown[:10])}")
    unusable = [s for s in scopes if not REGISTRY.peek(s).usable]
    if unusable:     # Day 11: no token for a tool that is switched off or misconfigured
        return await refuse(400, f"disabled or misconfigured tool scope(s): {', '.join(unusable)}")

    try:
        not_granted = [s for s in scopes if not await may_hold_scope(fga, agent_id, s)]
    except PolicyEngineError as exc:
        return await refuse(503, f"policy engine unavailable, failing closed: {exc}")
    if not_granted:
        return await refuse(403, f"agent '{agent_id}' may not hold: {', '.join(not_granted)}")

    # Session: reuse a session (taint and all), or start a new one.
    carried = None
    if login is not None:
        # Day 13: taint follows the agent. With the orchestrator, a trusted party decides when a
        # run (and its session) ends. An agent that logs in itself could otherwise read a
        # poisoned page and simply ask for a fresh, clean session.
        carried = await conn.fetchrow(
            """SELECT s.id, s.tainted_by FROM tokens t JOIN sessions s ON s.id = t.session_id
               WHERE t.agent_id = $1 AND t.expires_at > now() AND s.tainted
               ORDER BY s.tainted_at DESC NULLS LAST LIMIT 1""", agent_id)
    if session_id:
        try:
            sid = uuid.UUID(session_id)
        except ValueError:
            return await refuse(400, "session_id is not a UUID")
        row = await conn.fetchrow("SELECT owner FROM sessions WHERE id = $1", sid)
        if login is not None and (row is None or row["owner"] is None or row["owner"] != agent["owner"]):
            # Same answer for "doesn't exist" and "not yours", so session ids can't be probed.
            return await refuse(403, "unknown session, or not one this agent may join "
                                     "(an agent can only join a session started by an agent of the same owner)")
        if row is None:
            return await refuse(404, "unknown session_id")
    else:
        sid = uuid.uuid4()
        await conn.execute("INSERT INTO sessions (id, owner, created_by) VALUES ($1, $2, $3)", sid,
                           agent["owner"] if login is not None else None, agent_id if login is not None else None)
    if carried is not None and carried["id"] != sid:
        source = carried["tainted_by"] or "an earlier session"
        await taint.mark(conn, session_id=str(sid), tool=source, agent_id=agent_id,
                         via=f" (carried over: the agent still holds a token in tainted session {str(carried['id'])[:8]})")
    st = await taint.load(conn, str(sid))

    task_id = str(uuid.uuid4())
    token, claims = issue_token(state.key, settings, agent_id=agent_id, session_id=str(sid),
                                task_id=task_id, scopes=scopes)
    await conn.execute(
        """INSERT INTO tokens (jti, agent_id, session_id, task_id, task, scopes, issued_at, expires_at, login)
           VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7), to_timestamp($8), $9)""",
        uuid.UUID(claims["jti"]), agent_id, sid, uuid.UUID(task_id), task, scopes,
        claims["iat"], claims["exp"], login,
    )
    await audit.append_event(conn, event_type="token_issued", decision="info",
                             reason=f"scopes: {' '.join(scopes)}; task: {task[:120]}"
                                    + (f"; login: {login}" if login else ""),
                             agent_id=agent_id, session_id=str(sid), task_id=task_id, jti=claims["jti"],
                             session_tainted=st.tainted)
    return 201, TokenResponse(
        access_token=token, token_type="Bearer", expires_in=settings.token_ttl_seconds,
        expires_at=datetime.fromtimestamp(claims["exp"], tz=timezone.utc).isoformat(),
        agent_id=agent_id, session_id=str(sid), task_id=task_id, jti=claims["jti"], scopes=scopes,
        session_tainted=st.tainted, tainted_by=st.tainted_by, login=login,
    )


async def login_agent(state: State, conn: asyncpg.Connection, authorization: str | None, *,
                      what: str = "agent login") -> tuple[tuple[str, Login] | None, tuple[int, dict] | None]:
    """Day 13's check of an Auth0 bearer token, shared with the MCP gateway. `authorization` is the
    raw Authorization header.

    Returns ((agent_id, login), None) when the token is genuine and its Auth0 client is mapped to an
    agent, else (None, (status, body)). Refusals follow the Day 13 rules: a token that can't be tied
    to the issuer (alg swap, unknown key, bad signature) is 401, logged and NOT audited; a token the
    issuer really signed but that isn't usable (expired, another audience, a user's token) is 401
    and audited; an unmapped client is 403 and audited; no identity provider configured is 503.
    `what` only changes the words in the audit reason ("agent login", "MCP login")."""
    service = state.agent_login
    if service is None:
        return None, (503, {"error": "agent_login_not_configured",
                            "reason": "this broker has no identity provider configured for agent login"})
    try:
        login = await service.verify(agent_login.bearer_of(authorization))
    except Forged as exc:
        # Not provably from the issuer: refused and logged, but kept out of the audit chain
        # (like a bad signature on an agent token), so junk can't flood it.
        log.warning("%s refused: %s", what, exc.reason)
        return None, (401, {"error": "login_refused", "reason": exc.reason})
    except Unavailable as exc:
        return None, (503, {"error": "identity_provider_unavailable", "reason": exc.reason})
    except Rejected as exc:
        agent_id = (await conn.fetchval("SELECT id FROM agents WHERE auth0_client_id = $1", exc.client_id)
                    if exc.client_id else None)
        ev = await audit.append_event(
            conn, event_type="token_denied", decision="deny", agent_id=agent_id,
            reason=f"{what}: {exc.reason}" + (f" (Auth0 client {exc.client_id})" if exc.client_id else ""))
        return None, (401, {"error": "login_refused", "reason": exc.reason, "audit_id": ev["id"]})

    agent_id = await conn.fetchval("SELECT id FROM agents WHERE auth0_client_id = $1", login.client_id)
    if agent_id is None:
        reason = f"Auth0 client {login.client_id} is not mapped to an agent"
        ev = await audit.append_event(conn, event_type="token_denied", decision="deny", reason=f"{what}: {reason}")
        return None, (403, {"error": "login_refused", "reason": reason, "audit_id": ev["id"]})
    return (agent_id, login), None
