"""Day 12: the admin API that replaces the seed files.

    POST   /agents                          register an agent (DB row + owner tuple)
    PATCH  /agents/{id}                     display name, status (status uses the kill switch)
    GET    /agents/{id}/grants              its grants, read from OpenFGA
    POST   /agents/{id}/grants              {tool, mode?, params?}
    DELETE /agents/{id}/grants?tool=&mode=  remove API-made grants
    POST   /tools                           register a tool (a registry row)
    PATCH  /tools/{name}                    change a registry row
    DELETE /tools/{name}                    remove a row nothing refers to
    POST   /tools/{name}/approvers          {user}
    DELETE /tools/{name}/approvers/{user}

All of it needs the admin key. Every change is one event in the hash-chained audit log, with
who made it in the `approver` column ('admin-api', or 'admin-ui:<Auth0 sub>' when the admin
UI's server sends X-Admin-Via). Nothing here can read or return an upstream credential: a tool
row only names the env var that holds it.
"""

from __future__ import annotations

import unicodedata
from typing import Any

import asyncpg
import msgspec
from litestar import Request, Response, delete, get, patch, post
from litestar.datastructures import State
from litestar.di import Provide

from . import audit, delegation, grants, registry
from .deps import BadVia, _json, actor_of, admin_guard, provide_conn
from .fga import PolicyEngineError
from .grants import GrantError
from .registry import REGISTRY

_ADMIN = dict(guards=[admin_guard], dependencies={"conn": Provide(provide_conn)}, security=[{"AdminKey": []}])
_TOOL_COLUMNS = ("description", "args_schema", "risk_class", "context_map", "taints_session", "upstream",
                 "credential_ref", "enabled")


# ---------------------------------------------------------------- schemas


class AgentCreate(msgspec.Struct, forbid_unknown_fields=True):
    id: str
    owner: str                          # 'user:shiwin' (or 'shiwin')
    display_name: str | None = None


class AgentPatch(msgspec.Struct, forbid_unknown_fields=True):
    display_name: str | None = None
    status: str | None = None           # 'active' | 'disabled' (the kill switch)
    reason: str | None = None           # for the kill switch


class GrantRequest(msgspec.Struct, forbid_unknown_fields=True):
    tool: str
    mode: str | None = None             # omitted: `approval` for egress, money and destructive tools
    params: dict[str, Any] | None = None


class ToolCreate(msgspec.Struct, forbid_unknown_fields=True):
    name: str
    args_schema: dict[str, Any]
    risk_class: str
    upstream: dict[str, Any]
    description: str = ""
    context_map: dict[str, Any] = {}
    taints_session: bool = True         # safe default: its output is treated as untrusted
    credential_ref: str | None = None
    enabled: bool = False               # safe default: off until someone turns it on


class ToolPatch(msgspec.Struct, forbid_unknown_fields=True):
    description: str | msgspec.UnsetType = msgspec.UNSET
    args_schema: dict[str, Any] | msgspec.UnsetType = msgspec.UNSET
    risk_class: str | msgspec.UnsetType = msgspec.UNSET
    context_map: dict[str, Any] | msgspec.UnsetType = msgspec.UNSET
    taints_session: bool | msgspec.UnsetType = msgspec.UNSET
    upstream: dict[str, Any] | msgspec.UnsetType = msgspec.UNSET
    credential_ref: str | None | msgspec.UnsetType = msgspec.UNSET
    enabled: bool | msgspec.UnsetType = msgspec.UNSET


class ApproverRequest(msgspec.Struct, forbid_unknown_fields=True):
    user: str


# ---------------------------------------------------------------- helpers


def _refuse(status: int, error: str, reason: str) -> Response:
    return _json(status, {"error": error, "reason": reason})


def _actor(request: Request) -> tuple[str | None, Response | None]:
    try:
        return actor_of(request), None
    except BadVia as exc:
        return None, _refuse(400, "bad_request", str(exc))


def _plain(text: str, limit: int) -> bool:
    return 0 < len(text) <= limit and not any(unicodedata.category(c) in ("Cc", "Cf") for c in text)


async def kill_switch(conn: asyncpg.Connection, fga: Any, agent_id: str, reason: str, by: str = "admin-api") -> dict | None:
    """Disable an agent: every token it holds stops working at once, no new ones are issued, and
    every delegation it takes part in is revoked (Day 10). None if the agent is unknown."""
    async with conn.transaction():
        updated = await conn.fetchval("UPDATE agents SET status = 'disabled' WHERE id = $1 RETURNING id", agent_id)
        if updated is None:
            return None
        await conn.execute("INSERT INTO revocations (agent_id, reason) VALUES ($1, $2)", agent_id, reason)
    ev = await audit.append_event(conn, event_type="agent_disabled", decision="info", reason=reason,
                                  agent_id=agent_id)
    revoked = await delegation.revoke(conn, fga, where="delegator = $1 OR delegate = $1 OR principal = $1",
                                      args=[agent_id], reason=f"kill switch on agent:{agent_id}", by=by)
    return {"agent_id": agent_id, "status": "disabled", "audit_id": ev["id"], "delegations_revoked": revoked}


async def re_enable(conn: asyncpg.Connection, agent_id: str) -> dict | None:
    """Undo the kill switch. Old tokens stay revoked; the agent needs new ones."""
    updated = await conn.fetchval("UPDATE agents SET status = 'active' WHERE id = $1 RETURNING id", agent_id)
    if updated is None:
        return None
    ev = await audit.append_event(conn, event_type="agent_enabled", decision="info",
                                  reason="re-enabled by admin", agent_id=agent_id)
    return {"agent_id": agent_id, "status": "active", "audit_id": ev["id"]}


# ---------------------------------------------------------------- agents


@post("/agents", tags=["agents"], status_code=201, **_ADMIN)
async def register_agent(data: AgentCreate, request: Request, state: State, conn: asyncpg.Connection) -> Response:
    """Register an agent: a row in `agents` and its owner tuple in OpenFGA. A new agent has no
    grants, so every call it makes is denied until someone gives it one."""
    actor, bad = _actor(request)
    if bad:
        return bad
    if not grants.AGENT_ID.fullmatch(data.id):
        return _refuse(400, "invalid_agent", "id must match ^[a-z][a-z0-9_-]{1,63}$")
    name = data.display_name if data.display_name is not None else data.id
    if not _plain(name, 80):
        return _refuse(400, "invalid_agent", "display_name must be 1 to 80 printable characters")
    try:
        owner = grants.user_id(data.owner)
    except GrantError as exc:
        return _refuse(400, "invalid_agent", f"owner: {exc.reason}")
    key = {"user": owner, "relation": "owner", "object": f"agent:{data.id}"}
    try:
        async with conn.transaction():
            await conn.execute("INSERT INTO agents (id, owner, display_name, created_by) VALUES ($1, $2, $3, $4)",
                               data.id, owner, name, actor)
            if not await state.fga.read(key):
                await state.fga.write(writes=[key])
    except asyncpg.UniqueViolationError:
        return _refuse(409, "agent_exists", f"agent '{data.id}' is already registered")
    except PolicyEngineError as exc:
        return _refuse(503, "policy_engine_unavailable", f"nothing was changed: {exc}")
    ev = await audit.append_event(conn, event_type="agent_registered", decision="info", agent_id=data.id,
                                  approver=actor, reason=f"owner {owner}; no grants yet")
    return _json(201, {"id": data.id, "owner": owner, "display_name": name, "status": "active",
                       "grants": [], "audit_id": ev["id"]})


@patch("/agents/{agent_id:str}", tags=["agents"], status_code=200, **_ADMIN)
async def update_agent(agent_id: str, data: AgentPatch, request: Request, state: State,
                       conn: asyncpg.Connection) -> Response:
    """Change an agent's display name and/or status. Setting status to 'disabled' is the kill
    switch (tokens and delegations die); 'active' re-enables it."""
    actor, bad = _actor(request)
    if bad:
        return bad
    row = await conn.fetchrow("SELECT id, owner, display_name, status FROM agents WHERE id = $1", agent_id)
    if row is None:
        return _refuse(404, "unknown_agent", f"unknown agent '{agent_id[:64]}'")
    if data.status is not None and data.status not in ("active", "disabled"):
        return _refuse(400, "invalid_agent", "status must be 'active' or 'disabled'")
    if data.display_name is not None and not _plain(data.display_name, 80):
        return _refuse(400, "invalid_agent", "display_name must be 1 to 80 printable characters")
    out: dict[str, Any] = dict(row)
    if data.display_name is not None and data.display_name != row["display_name"]:
        await conn.execute("UPDATE agents SET display_name = $2 WHERE id = $1", agent_id, data.display_name)
        ev = await audit.append_event(conn, event_type="agent_updated", decision="info", agent_id=agent_id,
                                      approver=actor, reason="display name changed")
        out.update(display_name=data.display_name, audit_id=ev["id"])
    if data.status is not None and data.status != row["status"]:
        if data.status == "disabled":
            reason = data.reason if data.reason and _plain(data.reason, 200) else f"kill switch ({actor})"
            out.update(await kill_switch(conn, state.fga, agent_id, reason, by=actor) or {})
        else:
            out.update(await re_enable(conn, agent_id) or {})
    out.pop("agent_id", None)
    return _json(200, out)


# ---------------------------------------------------------------- grants


@get("/agents/{agent_id:str}/grants", tags=["grants"], **_ADMIN)
async def list_grants(agent_id: str, state: State, conn: asyncpg.Connection) -> Response:
    """One agent's grants, read from OpenFGA. `source` is 'api' (removable here) or 'seed'
    (policy/tuples.yaml); `grant_mode` is the mode name a POST would use."""
    if await conn.fetchval("SELECT 1 FROM agents WHERE id = $1", agent_id) is None:
        return _refuse(404, "unknown_agent", f"unknown agent '{agent_id[:64]}'")
    try:
        tuples = await state.fga.read()
    except PolicyEngineError as exc:
        return _refuse(503, "policy_engine_unavailable", str(exc))
    await REGISTRY.sync(conn)
    by_agent, _ = grants.view(tuples, await grants.managed_keys(conn))
    return _json(200, by_agent.get(agent_id, []))


@post("/agents/{agent_id:str}/grants", tags=["grants"], status_code=201, **_ADMIN)
async def add_grant(agent_id: str, data: GrantRequest, request: Request, state: State,
                    conn: asyncpg.Connection) -> Response:
    """Give an agent a grant on a registered tool. Without `mode`, an egress, money or
    destructive tool gets `approval`: a direct grant on those has to be asked for by name.
    The response carries a `warning` when the grant lets a risky tool run without a human."""
    actor, bad = _actor(request)
    if bad:
        return bad
    if await conn.fetchval("SELECT 1 FROM agents WHERE id = $1", agent_id) is None:
        return _refuse(404, "unknown_agent", f"unknown agent '{agent_id[:64]}'")
    tool = await REGISTRY.get(conn, data.tool) if registry.TOOL_NAME.fullmatch(data.tool) else None
    if tool is None:
        return _refuse(404, "unknown_tool", f"unknown tool '{data.tool[:64]}'")
    if tool.problem:
        return _refuse(400, "grant_refused", f"tool '{tool.name}' is misconfigured in the registry; fix it first")
    try:
        out = await grants.add(conn, state.fga, agent_id=agent_id, tool=tool, mode=data.mode, params=data.params,
                               actor=actor)
    except GrantError as exc:
        return _refuse(exc.status, "grant_refused", exc.reason)
    return _json(201, out)


@delete("/agents/{agent_id:str}/grants", tags=["grants"], status_code=200, **_ADMIN)
async def remove_grant(agent_id: str, request: Request, state: State, conn: asyncpg.Connection, tool: str,
                       mode: str | None = None) -> Response:
    """Remove an agent's API-made grant(s) on ?tool= (one ?mode=, or all of them). It applies to
    the very next call, also for tokens already issued. Seed-file grants are refused (409)."""
    actor, bad = _actor(request)
    if bad:
        return bad
    if not registry.TOOL_NAME.fullmatch(tool):
        return _refuse(404, "unknown_tool", f"unknown tool '{tool[:64]}'")
    try:
        removed = await grants.remove(conn, state.fga, agent_id=agent_id, tool=tool, mode=mode, actor=actor)
    except GrantError as exc:
        return _refuse(exc.status, "grant_not_removed", exc.reason)
    return _json(200, {"removed": removed})


# ---------------------------------------------------------------- tools


@post("/tools", tags=["tools"], status_code=201, request_max_body_size=registry.MAX_BODY_BYTES, **_ADMIN)
async def register_tool(data: ToolCreate, request: Request, conn: asyncpg.Connection) -> Response:
    """Add a tool to the registry. The row must be one the gate fully understands (a bad schema,
    context_map or upstream is refused with the reason). It starts disabled unless `enabled` is
    true, and has no grants: nobody can call it until an agent is granted it."""
    actor, bad = _actor(request)
    if bad:
        return bad
    row = {f: getattr(data, f) for f in ("name", *_TOOL_COLUMNS)}
    if len(row["description"]) > 500:
        return _refuse(400, "invalid_tool", "description must be at most 500 characters")
    tool = registry.compile_row(row)
    if tool.problem:
        return _refuse(400, "invalid_tool", tool.problem)
    try:
        async with REGISTRY.changing(conn, actor):
            await conn.execute(
                """INSERT INTO tools (name, description, args_schema, risk_class, context_map, taints_session,
                                      upstream, credential_ref, enabled, created_by)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)""",
                *(row[f] for f in ("name", *_TOOL_COLUMNS)), actor)
    except asyncpg.UniqueViolationError:
        return _refuse(409, "tool_exists", f"tool '{data.name}' is already registered (PATCH /tools/{data.name} changes it)")
    return _json(201, REGISTRY.peek(data.name).public())


@patch("/tools/{name:str}", tags=["tools"], status_code=200, request_max_body_size=registry.MAX_BODY_BYTES, **_ADMIN)
async def update_tool(name: str, data: ToolPatch, request: Request, conn: asyncpg.Connection) -> Response:
    """Change fields of a registry row. The result must be a row the gate fully understands;
    the one exception is switching a tool off, which always works. The gate uses the new row on
    the next call, and the change is audited with the old and new values of the small flags."""
    actor, bad = _actor(request)
    if bad:
        return bad
    changes = {f: getattr(data, f) for f in _TOOL_COLUMNS if getattr(data, f) is not msgspec.UNSET}
    current = await conn.fetchrow(f"SELECT name, version, {', '.join(_TOOL_COLUMNS)} FROM tools WHERE name = $1", name) \
        if registry.TOOL_NAME.fullmatch(name) else None
    if current is None:
        return _refuse(404, "unknown_tool", f"unknown tool '{name[:64]}'")
    if not changes:
        return _refuse(400, "invalid_tool", f"give at least one of: {', '.join(_TOOL_COLUMNS)}")
    if len(changes.get("description", "")) > 500:
        return _refuse(400, "invalid_tool", "description must be at most 500 characters")
    tool = registry.compile_row({**dict(current), **changes})
    switching_off = set(changes) == {"enabled"} and changes["enabled"] is False
    if tool.problem and not switching_off:
        return _refuse(400, "invalid_tool", tool.problem)
    sets = ", ".join(f"{col} = ${i}" for i, col in enumerate(changes, start=2))
    async with REGISTRY.changing(conn, actor):
        await conn.execute(f"UPDATE tools SET {sets} WHERE name = $1", name, *changes.values())
    return _json(200, REGISTRY.peek(name).public())


@delete("/tools/{name:str}", tags=["tools"], status_code=200, **_ADMIN)
async def remove_tool(name: str, request: Request, state: State, conn: asyncpg.Connection) -> Response:
    """Remove a registry row that nothing refers to. A tool with grants or approvers (from the
    API or the seed file) is refused: remove those first, or switch the tool off instead."""
    actor, bad = _actor(request)
    if bad:
        return bad
    if not registry.TOOL_NAME.fullmatch(name) or await REGISTRY.get(conn, name) is None:
        return _refuse(404, "unknown_tool", f"unknown tool '{name[:64]}'")
    try:
        in_use = bool(await state.fga.read({"object": f"tool:{name}"}))
    except PolicyEngineError as exc:
        return _refuse(503, "policy_engine_unavailable", f"nothing was changed: {exc}")
    in_use = in_use or await conn.fetchval(
        "SELECT EXISTS (SELECT 1 FROM grants WHERE tool = $1) OR EXISTS (SELECT 1 FROM tool_approvers WHERE tool = $1)", name)
    if in_use:
        return _refuse(409, "tool_in_use", f"tool '{name}' still has grants or approvers; remove them first, "
                                           "or switch it off with PATCH {\"enabled\": false}")
    async with REGISTRY.changing(conn, actor):
        await conn.execute("DELETE FROM tools WHERE name = $1", name)
    return _json(200, {"removed": name})


@post("/tools/{name:str}/approvers", tags=["tools"], status_code=201, **_ADMIN)
async def add_tool_approver(name: str, data: ApproverRequest, request: Request, state: State,
                            conn: asyncpg.Connection) -> Response:
    """Let a human approve this tool's escalations (OpenFGA: user:<name> approver tool:<name>).
    For Slack clicks the user also needs a SLACK_APPROVERS mapping; for the admin UI, APPROVERS."""
    actor, bad = _actor(request)
    if bad:
        return bad
    if not registry.TOOL_NAME.fullmatch(name) or await REGISTRY.get(conn, name) is None:
        return _refuse(404, "unknown_tool", f"unknown tool '{name[:64]}'")
    try:
        out = await grants.add_approver(conn, state.fga, tool=name, user=grants.user_id(data.user), actor=actor)
    except GrantError as exc:
        return _refuse(exc.status, "approver_not_added", exc.reason)
    return _json(201, out)


@delete("/tools/{name:str}/approvers/{user:str}", tags=["tools"], status_code=200, **_ADMIN)
async def remove_tool_approver(name: str, user: str, request: Request, state: State,
                               conn: asyncpg.Connection) -> Response:
    actor, bad = _actor(request)
    if bad:
        return bad
    if not registry.TOOL_NAME.fullmatch(name):
        return _refuse(404, "unknown_tool", f"unknown tool '{name[:64]}'")
    try:
        out = await grants.remove_approver(conn, state.fga, tool=name, user=grants.user_id(user), actor=actor)
    except GrantError as exc:
        return _refuse(exc.status, "approver_not_removed", exc.reason)
    return _json(200, out)


ROUTES = [register_agent, update_agent, list_grants, add_grant, remove_grant, register_tool, update_tool,
          remove_tool, add_tool_approver, remove_tool_approver]
