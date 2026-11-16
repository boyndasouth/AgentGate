"""Day 10: delegation chains. Agent A grants agent B part of its access; B trades its own token
for one that acts on A's behalf (RFC 8693-style token exchange); B may pass it on once more.

The rules, in one place:
  - A delegate can never do more than the agent it acts for. A delegated call is judged AS the
    principal (its grants, conditions, limits, allowlists), never with the delegate's own grants.
  - Only tools in the granting token's scopes can be delegated, and only to an active agent with
    the same human owner (checked in OpenFGA: user:<owner> owner agent:<delegate>).
  - At most 2 hops (A -> B -> C). No cycles. A child never outlives its parent.
  - A session that has read untrusted content can't grant access, and the delegator's session
    taint follows the grant: a delegated call counts as tainted if any session in the chain is.
  - Every hop must be live on every call: the DB row not revoked, and in OpenFGA the delegate
    still holds it before its expiry and it still covers the tool.
  - Revoking a delegation revokes everything granted from it. The kill switch on any agent
    revokes every delegation it takes part in, and they stay revoked after re-enabling.

The OpenFGA tuples ARE the grant (policy/model.fga, type delegation); the `delegations` table is
the record the gate uses for revocation, depth and taint.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import asyncpg

from . import audit, taint
from .decision import may_hold_scope
from .fga import FGAClient, PolicyEngineError
from .tokens import AgentClaims

MAX_DEPTH = 2
MIN_TTL_SECONDS, MAX_TTL_SECONDS = 30, 3600


class DelegationError(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status, self.reason = status, reason


def rfc3339(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _short(ids) -> str:
    return " -> ".join(str(i)[:8] for i in ids)


@dataclass(frozen=True)
class Grant:
    id: str
    principal: str
    delegator: str
    delegate: str
    tools: tuple[str, ...]
    parent_id: str | None
    depth: int
    expires_at: datetime


def _grant(row) -> Grant:
    return Grant(str(row["id"]), row["principal"], row["delegator"], row["delegate"], tuple(row["tools"]),
                 str(row["parent_id"]) if row["parent_id"] else None, row["depth"], row["expires_at"])


def tuples_for(g: Grant) -> list[dict]:
    obj = f"delegation:{g.id}"
    out = [
        {"user": f"agent:{g.delegator}", "relation": "delegator", "object": obj},
        {"user": f"agent:{g.delegate}", "relation": "delegate", "object": obj,
         "condition": {"name": "not_expired", "context": {"expires_at": rfc3339(g.expires_at)}}},
        *({"user": f"tool:{t}", "relation": "covers", "object": obj} for t in g.tools),
    ]
    if g.parent_id:
        out.append({"user": f"delegation:{g.parent_id}", "relation": "parent", "object": obj})
    return out


# ---------------------------------------------------------------- taint across the chain


async def effective_taint(conn: asyncpg.Connection, claims: AgentClaims,
                          own: taint.SessionTaint | None) -> taint.SessionTaint | None:
    """The calling session's taint, OR the taint of any session a delegation in the chain was
    granted from, read now (so a delegator's session tainted after the grant still counts)."""
    if not claims.delegated or own is None or own.tainted:
        return own
    row = await conn.fetchrow(
        """SELECT s.tainted_by FROM delegations d JOIN sessions s ON s.id = d.origin_session
           WHERE d.id = ANY($1::uuid[]) AND s.tainted ORDER BY d.depth LIMIT 1""",
        [uuid.UUID(d) for d in claims.delegation_ids])
    if row is None:
        return own
    return taint.SessionTaint(True, f"{row['tainted_by']} (delegator's session)")


# ---------------------------------------------------------------- liveness (every delegated call)


async def live(conn: asyncpg.Connection, fga: FGAClient, claims: AgentClaims, tool: str) -> str | None:
    """None if every hop is live and covers `tool`; otherwise the reason to deny."""
    rows = {str(r["id"]): r for r in await conn.fetch(
        "SELECT * FROM delegations WHERE id = ANY($1::uuid[])", [uuid.UUID(d) for d in claims.delegation_ids])}
    now = _now()
    # actors are calling-agent first; delegation ids are root first. Hop i's delegate is actors[-1-i].
    for i, did in enumerate(claims.delegation_ids):
        row = rows.get(did)
        if row is None or row["principal"] != claims.principal or row["delegate"] != claims.actors[-1 - i]:
            return f"delegation {did[:8]} does not match this token"
        if row["revoked_at"] is not None:
            return f"delegation {did[:8]} was revoked"
        if row["expires_at"] <= now:
            return f"delegation {did[:8]} has expired"
        if not await fga.check(f"agent:{row['delegate']}", "delegate", f"delegation:{did}",
                               {"current_time": rfc3339(now)}):
            return f"delegation {did[:8]} is no longer held by agent '{row['delegate']}' (expired or removed)"
        if not await fga.check(f"tool:{tool}", "covers", f"delegation:{did}", {}):
            return f"delegation {did[:8]} does not cover '{tool}'"
    return None


# ---------------------------------------------------------------- grant


async def grant(conn: asyncpg.Connection, fga: FGAClient, claims: AgentClaims, *, delegate: str,
                tools: list[str], ttl_seconds: int, task: str) -> dict:
    """The holder of `claims` grants `delegate` some of its tools. Raises DelegationError."""
    tools = sorted(set(tools))
    depth = len(claims.delegation_ids) + 1
    if depth > MAX_DEPTH:
        raise DelegationError(403, f"delegation chains are limited to {MAX_DEPTH} hops")
    if not tools:
        raise DelegationError(400, "delegate at least one tool")
    outside = [t for t in tools if t not in claims.scopes]
    if outside:
        raise DelegationError(403, f"can only delegate tools in this token's scopes, not: {', '.join(outside)}")
    if not MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS:
        raise DelegationError(400, f"ttl_seconds must be {MIN_TTL_SECONDS}-{MAX_TTL_SECONDS}")
    if delegate in claims.chain:
        raise DelegationError(403, f"agent '{delegate}' is already in this chain (no cycles)")
    target = await conn.fetchrow("SELECT id, status FROM agents WHERE id = $1", delegate)
    if target is None:
        raise DelegationError(404, f"unknown agent '{delegate}'")
    if target["status"] != "active":
        raise DelegationError(403, f"agent '{delegate}' is disabled (kill switch)")

    st = await effective_taint(conn, claims, await taint.load(conn, claims.session_id))
    if st and st.tainted:
        raise DelegationError(403, f"a tainted session can't grant access (tainted by {st.tainted_by})")

    owner = await conn.fetchval("SELECT owner FROM agents WHERE id = $1", claims.principal)
    if not owner or not await fga.check(owner, "owner", f"agent:{delegate}", {}):
        raise DelegationError(403, f"agent '{delegate}' has a different owner than agent '{claims.principal}'")
    lost = [t for t in tools if not await may_hold_scope(fga, claims.principal, t)]
    if lost:
        raise DelegationError(403, f"agent '{claims.principal}' no longer holds: {', '.join(lost)}")

    expires = _now() + timedelta(seconds=ttl_seconds)
    parent_id = claims.delegation_ids[-1] if claims.delegation_ids else None
    if parent_id:
        if (why := await live(conn, fga, claims, tools[0])) is not None:
            raise DelegationError(403, why)
        for t in tools[1:]:
            if (why := await live(conn, fga, claims, t)) is not None:
                raise DelegationError(403, why)
        parent_exp = await conn.fetchval("SELECT expires_at FROM delegations WHERE id = $1", uuid.UUID(parent_id))
        expires = min(expires, parent_exp)            # a child never outlives its parent

    g = Grant(str(uuid.uuid4()), claims.principal, claims.agent_id, delegate, tuple(tools), parent_id, depth, expires)
    async with conn.transaction():
        await conn.execute(
            """INSERT INTO delegations (id, principal, delegator, delegate, tools, parent_id, depth,
                                        origin_session, created_jti, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)""",
            uuid.UUID(g.id), g.principal, g.delegator, g.delegate, list(g.tools),
            uuid.UUID(parent_id) if parent_id else None, depth, uuid.UUID(claims.session_id),
            uuid.UUID(claims.jti), expires)
        await fga.write(writes=tuples_for(g))          # if this fails, the row rolls back
    via = f" via {_short(claims.delegation_ids)}" if claims.delegated else ""
    ev = await audit.append_event(
        conn, event_type="delegation_granted", decision="info",
        reason=(f"delegation {g.id}: agent:{delegate} may act for agent:{g.principal} on {', '.join(tools)} "
                f"until {rfc3339(expires)} (hop {depth}{via}); task: {task[:100]}"),
        agent_id=claims.agent_id, session_id=claims.session_id, task_id=claims.task_id, jti=claims.jti,
        session_tainted=False)
    return {"delegation_id": g.id, "principal": g.principal, "delegator": g.delegator, "delegate": delegate,
            "tools": list(tools), "depth": depth, "parent_id": parent_id, "expires_at": rfc3339(expires),
            "audit_id": ev["id"]}


# ---------------------------------------------------------------- exchange


async def chain_for(conn: asyncpg.Connection, delegation_id: str) -> list[Grant]:
    """The delegation and its ancestors, root first."""
    try:
        did = uuid.UUID(delegation_id)
    except ValueError as exc:
        raise DelegationError(400, "delegation_id is not a UUID") from exc
    rows = await conn.fetch(
        """WITH RECURSIVE up AS (
             SELECT * FROM delegations WHERE id = $1
             UNION ALL SELECT d.* FROM delegations d JOIN up ON d.id = up.parent_id)
           SELECT * FROM up ORDER BY depth""", did)
    if not rows:
        raise DelegationError(404, "unknown delegation")
    return [_grant(r) for r in rows]


async def prepare_exchange(conn: asyncpg.Connection, fga: FGAClient, subject: AgentClaims, *,
                           delegation_id: str, scopes: list[str]) -> tuple[list[Grant], list[str]]:
    """Checks for POST /tokens/exchange. The subject token is the delegate's OWN plain token: it
    proves who is asking and which session (taint) the new token lives in. Returns (chain, actors)."""
    if subject.delegated:
        raise DelegationError(400, "exchange starts from the agent's own token, not a delegated one")
    chain = await chain_for(conn, delegation_id)
    leaf = chain[-1]
    if leaf.delegate != subject.agent_id:
        raise DelegationError(403, f"delegation {delegation_id[:8]} was not granted to agent '{subject.agent_id}'")
    scopes = sorted(set(scopes))
    if not scopes:
        raise DelegationError(400, "request at least one scope")
    outside = [s for s in scopes if s not in leaf.tools]
    if outside:
        raise DelegationError(403, f"delegation {delegation_id[:8]} doesn't cover: {', '.join(outside)}")
    actors = [g.delegate for g in reversed(chain)]          # calling agent first
    probe = AgentClaims(agent_id=subject.agent_id, session_id=subject.session_id, task_id=subject.task_id,
                        scopes=frozenset(scopes), jti=subject.jti, issued_at=subject.issued_at,
                        expires_at=subject.expires_at, principal=chain[0].principal, actors=tuple(actors),
                        delegation_ids=tuple(g.id for g in chain))
    for s in scopes:
        if (why := await live(conn, fga, probe, s)) is not None:
            raise DelegationError(403, why)
    agents = {chain[0].principal, *actors}
    inactive = await conn.fetchval(
        "SELECT array_agg(id ORDER BY id) FROM agents WHERE id = ANY($1::text[]) AND status <> 'active'", list(agents))
    if inactive:
        raise DelegationError(403, f"agent '{inactive[0]}' in the chain is disabled (kill switch)")
    return chain, actors


# ---------------------------------------------------------------- revoke


async def revoke(conn: asyncpg.Connection, fga: FGAClient, *, where: str, args: list, reason: str,
                 by: str | None = None) -> list[str]:
    """Revoke the matching live delegations and everything granted from them. `where` is a SQL
    condition on `delegations` (fixed strings from this module's callers, never user input).
    The DB row is authoritative (the gate checks it on every call); the OpenFGA tuples are then
    removed so a check can't pass on its own. Returns the revoked ids."""
    async with conn.transaction():
        rows = await conn.fetch(
            f"""WITH RECURSIVE hit AS (
                  SELECT id FROM delegations WHERE revoked_at IS NULL AND ({where})
                  UNION SELECT d.id FROM delegations d JOIN hit ON d.parent_id = hit.id WHERE d.revoked_at IS NULL)
                UPDATE delegations SET revoked_at = now(), revoked_reason = ${len(args) + 1}
                WHERE id IN (SELECT id FROM hit) RETURNING *""", *args, reason)
    grants = [_grant(r) for r in rows]
    for g in grants:
        await audit.append_event(conn, event_type="delegation_revoked", decision="info",
                                 reason=f"delegation {g.id}: {reason}", agent_id=g.delegate, approver=by)
    try:
        dels = [t for g in grants for t in tuples_for(g)]
        for i in range(0, len(dels), 100):           # OpenFGA takes up to 100 tuples per write
            await fga.write(deletes=dels[i:i + 100])
    except PolicyEngineError:
        pass   # the revoked rows already deny every call; a stale tuple grants nothing on its own
    return [g.id for g in grants]


async def listing(conn: asyncpg.Connection, *, active_only: bool = True, limit: int = 100) -> list[dict]:
    q = "SELECT * FROM delegations"
    if active_only:
        q += " WHERE revoked_at IS NULL AND expires_at > now()"
    rows = await conn.fetch(q + " ORDER BY created_at DESC LIMIT $1", max(1, min(limit, 500)))
    return [{"id": str(r["id"]), "principal": r["principal"], "delegator": r["delegator"], "delegate": r["delegate"],
             "tools": list(r["tools"]), "depth": r["depth"],
             "parent_id": str(r["parent_id"]) if r["parent_id"] else None,
             "created_at": r["created_at"].isoformat(), "expires_at": r["expires_at"].isoformat(),
             "revoked_at": r["revoked_at"].isoformat() if r["revoked_at"] else None,
             "revoked_reason": r["revoked_reason"]} for r in rows]
