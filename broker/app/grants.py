"""Day 12: grants, approvers and agent owners made through the admin API.

OpenFGA stays the only thing the gate asks. This module turns an API request into the tuple
(and condition) that expresses it, writes it to OpenFGA, and keeps a row in Postgres:

    grants          one row per (agent, tool, relation), with the tuple exactly as written
    tool_approvers  one row per (tool, user)
    agents          the owner column is the owner tuple

Why the rows: the boot-time sync (deploy/render/seed_fga.py) makes the store equal to
policy/tuples.yaml PLUS these rows, so a redeploy keeps what the API wrote, and `reconcile()`
writes them again into a store that lost them (a local `load_store.py --replace`).

Two owners, no overlap: a tuple that is in OpenFGA but has no row here comes from the seed file
and is refused by this API (409), so the file and the API can never fight over the same tuple.

Grant modes (the request names a mode, never a raw tuple):

    direct                            direct_invoker, no condition
    direct_if_untainted               direct_invoker with `untainted`
    direct_allowlisted_recipient      ... with `untainted_allowed_recipient`   {allowed_recipient_domains}
    direct_known_payee_with_invoice   ... with `within_limit_open_invoice`     {max_amount, allowed_payees}
    direct_allowed_host               ... with `untainted_or_allowed_host`     {allowed_hosts}
    approval                          approval_invoker: every call goes to a human

Safe default: when the request names no mode, a tool whose risk class is egress, money or
destructive gets `approval`. A direct mode on such a tool has to be asked for by name.
"""

from __future__ import annotations

import logging
import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping

import asyncpg

from . import audit
from .fga import FGAClient, PolicyEngineError
from .registry import REGISTRY, Tool

log = logging.getLogger("agentgate.grants")

AGENT_ID = re.compile(r"[a-z][a-z0-9_-]{1,63}")
USER_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_DOMAIN = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+")
_HOST = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*")
MAX_LIST = 50
RISKY = ("egress", "money", "destructive")


class GrantError(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status, self.reason = status, reason


@dataclass(frozen=True)
class Mode:
    relation: str
    condition: str | None = None
    params: tuple[str, ...] = ()
    needs: tuple[str, ...] = ()      # context_map keys the tool must have for the condition to mean anything


MODES: dict[str, Mode] = {
    "direct": Mode("direct_invoker"),
    "direct_if_untainted": Mode("direct_invoker", "untainted"),
    "direct_allowlisted_recipient": Mode("direct_invoker", "untainted_allowed_recipient",
                                         ("allowed_recipient_domains",), ("recipient",)),
    "direct_known_payee_with_invoice": Mode("direct_invoker", "within_limit_open_invoice",
                                            ("max_amount", "allowed_payees"), ("amount", "payee", "invoice")),
    "direct_allowed_host": Mode("direct_invoker", "untainted_or_allowed_host", ("allowed_hosts",), ("url",)),
    "approval": Mode("approval_invoker"),
}
_BY_TUPLE = {(m.relation, m.condition): name for name, m in MODES.items()}


def default_mode(risk_class: str) -> str:
    """The mode a grant gets when the request names none."""
    if risk_class in RISKY:
        return "approval"
    return "direct_if_untainted" if risk_class == "write" else "direct"


def mode_of(relation: str, condition: str | None) -> str | None:
    return _BY_TUPLE.get((relation, condition))


def user_id(raw: Any) -> str:
    """'shiwin' or 'user:shiwin' -> 'user:shiwin'. Raises GrantError(400)."""
    name = raw.removeprefix("user:") if isinstance(raw, str) else ""
    if not USER_NAME.fullmatch(name):
        raise GrantError(400, "a user must look like 'user:<name>' (lower-case letters, digits, '_', '.', '-')")
    return f"user:{name}"


# ---------------------------------------------------------------- params


def _names(value: Any, key: str, pattern: re.Pattern | None) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_LIST:
        raise GrantError(400, f"params.{key} must be a list of 1 to {MAX_LIST} strings")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not 1 <= len(item) <= 128:
            raise GrantError(400, f"params.{key} must hold strings of 1 to 128 characters")
        if pattern is not None:
            item = item.lower()
            if not pattern.fullmatch(item):
                raise GrantError(400, f"params.{key} has an entry that isn't a plain host or domain name "
                                      "(exact names only, no wildcards)")
        elif any(unicodedata.category(c) == "Cc" for c in item):
            raise GrantError(400, f"params.{key} has an entry with a control character")
        if item not in out:
            out.append(item)
    return out


def clean_params(mode: str, params: Any) -> dict:
    """Validate a mode's params and return them as they go into the tuple's condition context."""
    spec = MODES[mode]
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise GrantError(400, "params must be an object")
    extra, missing = sorted(set(params) - set(spec.params)), [k for k in spec.params if k not in params]
    if extra:
        raise GrantError(400, f"mode '{mode}' takes " + (f"only {', '.join(spec.params)}" if spec.params else "no params"))
    if missing:
        raise GrantError(400, f"mode '{mode}' needs params.{missing[0]}")
    out: dict[str, Any] = {}
    for key in spec.params:
        value = params[key]
        if key == "max_amount":
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) \
                    or not 0 < value <= 1_000_000_000:
                raise GrantError(400, "params.max_amount must be a number above 0")
            out[key] = float(value)
        elif key == "allowed_payees":
            out[key] = _names(value, key, None)        # judged exactly as sent, like the argument (Day 9)
        else:
            out[key] = _names(value, key, _DOMAIN if key == "allowed_recipient_domains" else _HOST)
    return out


def tuple_key(agent_id: str, tool: str, mode: str, params: Mapping[str, Any]) -> dict:
    spec = MODES[mode]
    key: dict[str, Any] = {"user": f"agent:{agent_id}", "relation": spec.relation, "object": f"tool:{tool}"}
    if spec.condition:
        key["condition"] = {"name": spec.condition, **({"context": dict(params)} if params else {})}
    return key


def describe(mode: str, params: Mapping[str, Any]) -> str:
    """A grant in words, for the audit log. Payee accounts are counted, not listed (Day 9)."""
    bits = []
    for key, value in params.items():
        if key == "max_amount":
            bits.append(f"max_amount {value:g}")
        elif key == "allowed_payees":
            bits.append(f"{len(value)} allowed payee{'s' if len(value) != 1 else ''}")
        else:
            shown = ", ".join(value[:5]) + (" ..." if len(value) > 5 else "")
            bits.append(f"{key} [{shown}]")
    return mode + (f" ({'; '.join(bits)})" if bits else "")


def warning_for(tool: Tool, mode: str, has_approver: bool) -> str | None:
    if mode == "approval":
        return None if has_approver else (f"no approver is set for '{tool.name}': escalations will time out "
                                          "as a deny until one is added")
    if tool.risk_class in RISKY and mode in ("direct", "direct_if_untainted"):
        how = "with no condition at all" if mode == "direct" else "whenever the session is clean"
        return (f"'{tool.name}' is a {tool.risk_class} tool and this grant lets the agent run it without "
                f"a human, {how}")
    return None


# ---------------------------------------------------------------- reading


async def _stored(fga: FGAClient, key: Mapping[str, Any]) -> bool:
    return bool(await fga.read({k: key[k] for k in ("user", "relation", "object")}))


async def managed_keys(conn: asyncpg.Connection) -> set[tuple[str, str, str]]:
    """(user, relation, object) of every tuple this API owns."""
    rows = await conn.fetch("SELECT agent_id, tool, relation FROM grants")
    keys = {(f"agent:{r['agent_id']}", r["relation"], f"tool:{r['tool']}") for r in rows}
    rows = await conn.fetch("SELECT tool, user_id FROM tool_approvers")
    return keys | {(r["user_id"], "approver", f"tool:{r['tool']}") for r in rows}


def view(tuples: list[dict], managed: set[tuple[str, str, str]]) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    """OpenFGA tuples as (grants by agent id, approvers by tool name). `source` says who owns a
    tuple: 'api' (it can be removed through this API) or 'seed' (policy/tuples.yaml)."""
    approvers: dict[str, list[dict]] = {}
    grants: dict[str, list[dict]] = {}
    for t in tuples:
        if not t["object"].startswith("tool:"):
            continue
        tool = t["object"][5:]
        source = "api" if (t["user"], t["relation"], t["object"]) in managed else "seed"
        if t["relation"] == "approver":
            approvers.setdefault(tool, []).append({"user": t["user"], "source": source})
        elif t["user"].startswith("agent:") and t["relation"] in ("direct_invoker", "approval_invoker"):
            cond = t.get("condition") or {}
            known = REGISTRY.peek(tool)
            grants.setdefault(t["user"][6:], []).append({
                "tool": tool, "mode": "direct" if t["relation"] == "direct_invoker" else "approval",
                "grant_mode": mode_of(t["relation"], cond.get("name")),
                "condition": cond.get("name"), "context": cond.get("context") or {},
                "taints": bool(known.taints) if known else False,
                "risk_class": known.risk_class if known else None,
                "source": source, "approvers": None})
    for gs in grants.values():
        for g in gs:
            g["approvers"] = sorted(a["user"] for a in approvers.get(g["tool"], []))
        gs.sort(key=lambda g: (g["tool"], g["mode"] != "direct"))
    for who in approvers.values():
        who.sort(key=lambda a: a["user"])
    return grants, approvers


# ---------------------------------------------------------------- writing


async def add(conn: asyncpg.Connection, fga: FGAClient, *, agent_id: str, tool: Tool, mode: str | None,
              params: Any, actor: str) -> dict:
    """Give an agent a grant on a tool. Raises GrantError; on success the tuple is in OpenFGA,
    the row is in `grants` and a `grant_added` event is in the audit log."""
    explicit = mode is not None
    mode = mode if explicit else default_mode(tool.risk_class)
    if mode not in MODES:
        raise GrantError(400, f"mode must be one of {', '.join(MODES)}")
    spec = MODES[mode]
    params = clean_params(mode, params)
    lacking = [k for k in spec.needs if k not in tool.context_map]
    if lacking:
        raise GrantError(400, f"mode '{mode}' needs the tool's context_map to map {', '.join(spec.needs)}; "
                              f"'{tool.name}' doesn't map {', '.join(lacking)}, so the condition could never hold")
    key = tuple_key(agent_id, tool.name, mode, params)
    try:
        async with conn.transaction():
            held = await conn.fetchval("SELECT mode FROM grants WHERE agent_id = $1 AND tool = $2 AND relation = $3",
                                       agent_id, tool.name, spec.relation)
            if held:
                raise GrantError(409, f"agent '{agent_id}' already has a '{held}' grant on '{tool.name}'; "
                                      "remove it first")
            if await _stored(fga, key):
                raise GrantError(409, f"that grant on '{tool.name}' is set in policy/tuples.yaml (the seed file); "
                                      "change it there")
            await conn.execute(
                """INSERT INTO grants (agent_id, tool, relation, mode, params, fga_tuple, created_by)
                   VALUES ($1, $2, $3, $4, $5, $6, $7)""",
                agent_id, tool.name, spec.relation, mode, params, key, actor)
            await fga.write(writes=[key])     # last: if it fails, the row is rolled back
            has_approver = bool(await fga.read({"relation": "approver", "object": f"tool:{tool.name}"}))
    except asyncpg.UniqueViolationError:
        raise GrantError(409, f"agent '{agent_id}' already has that kind of grant on '{tool.name}'") from None
    except PolicyEngineError as exc:
        raise GrantError(503, f"policy engine unavailable, nothing was changed: {exc}") from None
    warning = warning_for(tool, mode, has_approver)
    why = describe(mode, params) + ("" if explicit else f" [the default for a {tool.risk_class} tool]")
    if warning and mode != "approval":
        why += f"; a direct grant on a {tool.risk_class} tool"
    ev = await audit.append_event(conn, event_type="grant_added", decision="info", agent_id=agent_id,
                                  tool=tool.name, approver=actor, reason=why[:300])
    return {"agent_id": agent_id, "tool": tool.name, "mode": mode, "params": params, "risk_class": tool.risk_class,
            "defaulted": not explicit, "warning": warning, "audit_id": ev["id"]}


async def remove(conn: asyncpg.Connection, fga: FGAClient, *, agent_id: str, tool: str, mode: str | None,
                 actor: str) -> list[dict]:
    """Remove an agent's grant(s) on a tool: the named mode, or every API-made one. The next call
    is judged without it, live tokens included."""
    if mode is not None and mode not in MODES:
        raise GrantError(400, f"mode must be one of {', '.join(MODES)}")
    try:
        async with conn.transaction():
            rows = await conn.fetch(
                """DELETE FROM grants WHERE agent_id = $1 AND tool = $2 AND ($3::text IS NULL OR mode = $3)
                   RETURNING relation, mode, params, fga_tuple""", agent_id, tool, mode)
            if not rows:
                relations = [MODES[mode].relation] if mode else ["direct_invoker", "approval_invoker"]
                for relation in relations:
                    if await _stored(fga, {"user": f"agent:{agent_id}", "relation": relation, "object": f"tool:{tool}"}):
                        raise GrantError(409, f"that grant of agent '{agent_id}' on '{tool}' wasn't made through "
                                              "the API: it comes from policy/tuples.yaml (the seed file) or "
                                              "has a different mode")
                raise GrantError(404, f"agent '{agent_id}' has no {mode + ' ' if mode else ''}grant on '{tool}'")
            gone = [r["fga_tuple"] for r in rows if await _stored(fga, r["fga_tuple"])]
            await fga.write(deletes=gone)
    except PolicyEngineError as exc:
        raise GrantError(503, f"policy engine unavailable, nothing was changed: {exc}") from None
    out = []
    for r in rows:
        ev = await audit.append_event(conn, event_type="grant_removed", decision="info", agent_id=agent_id,
                                      tool=tool, approver=actor, reason=describe(r["mode"], r["params"])[:300])
        out.append({"agent_id": agent_id, "tool": tool, "mode": r["mode"], "audit_id": ev["id"]})
    return out


async def add_approver(conn: asyncpg.Connection, fga: FGAClient, *, tool: str, user: str, actor: str) -> dict:
    key = {"user": user, "relation": "approver", "object": f"tool:{tool}"}
    try:
        async with conn.transaction():
            if await _stored(fga, key):
                raise GrantError(409, f"{user} is already an approver of '{tool}'")
            await conn.execute("INSERT INTO tool_approvers (tool, user_id, created_by) VALUES ($1, $2, $3)",
                               tool, user, actor)
            await fga.write(writes=[key])
    except asyncpg.UniqueViolationError:
        raise GrantError(409, f"{user} is already an approver of '{tool}'") from None
    except PolicyEngineError as exc:
        raise GrantError(503, f"policy engine unavailable, nothing was changed: {exc}") from None
    ev = await audit.append_event(conn, event_type="approver_added", decision="info", tool=tool, approver=actor,
                                  reason=f"{user} may approve escalations of {tool}")
    return {"tool": tool, "user": user, "audit_id": ev["id"]}


async def remove_approver(conn: asyncpg.Connection, fga: FGAClient, *, tool: str, user: str, actor: str) -> dict:
    key = {"user": user, "relation": "approver", "object": f"tool:{tool}"}
    try:
        async with conn.transaction():
            row = await conn.fetchrow("DELETE FROM tool_approvers WHERE tool = $1 AND user_id = $2 RETURNING tool",
                                      tool, user)
            stored = await _stored(fga, key)
            if row is None:
                if stored:
                    raise GrantError(409, f"{user} is an approver of '{tool}' through policy/tuples.yaml "
                                          "(the seed file); change it there")
                raise GrantError(404, f"{user} is not an approver of '{tool}'")
            if stored:
                await fga.write(deletes=[key])
    except PolicyEngineError as exc:
        raise GrantError(503, f"policy engine unavailable, nothing was changed: {exc}") from None
    ev = await audit.append_event(conn, event_type="approver_removed", decision="info", tool=tool, approver=actor,
                                  reason=f"{user} may no longer approve escalations of {tool}")
    return {"tool": tool, "user": user, "audit_id": ev["id"]}


# ---------------------------------------------------------------- keeping the store in step


async def desired(conn: asyncpg.Connection) -> list[dict]:
    """Every tuple the API owns, as tuple keys: owners, grants, approvers."""
    out = [{"user": r["owner"], "relation": "owner", "object": f"agent:{r['id']}"}
           for r in await conn.fetch("SELECT id, owner FROM agents ORDER BY id")]
    out += [dict(r["fga_tuple"]) for r in await conn.fetch("SELECT fga_tuple FROM grants ORDER BY agent_id, tool")]
    out += [{"user": r["user_id"], "relation": "approver", "object": f"tool:{r['tool']}"}
            for r in await conn.fetch("SELECT tool, user_id FROM tool_approvers ORDER BY tool, user_id")]
    return out


async def reconcile(conn: asyncpg.Connection, fga: FGAClient) -> tuple[int, int]:
    """At startup: write every API-owned tuple the store doesn't have (a fresh local store after
    `load_store.py --replace`; on Render the boot-time sync has kept them already). Never deletes.
    Returns (written, in the store with a different condition: left alone and logged)."""
    current = {(t["user"], t["relation"], t["object"]): t for t in await fga.read()}
    missing, differing = [], 0
    for t in await desired(conn):
        have = current.get((t["user"], t["relation"], t["object"]))
        if have is None:
            missing.append(t)
        elif (have.get("condition") or {}).get("name") != (t.get("condition") or {}).get("name"):
            differing += 1
            log.warning("tuple %s %s %s is in OpenFGA with a different condition than the API recorded; "
                        "left as it is", t["user"], t["relation"], t["object"])
    for i in range(0, len(missing), 50):
        await fga.write(writes=missing[i:i + 50])
    return len(missing), differing
