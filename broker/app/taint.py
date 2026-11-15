"""Session taint tracking (Day 5): information-flow control for agent sessions.

One session = one orchestrator run, shared by every agent in it. Once any agent in
the session receives untrusted outside content (a tool with `taints=True`, today
`read_web` and `read_inbox`), the gate marks the whole session tainted. The policy
then sees `session_tainted = true`, so conditional grants like
`send_email ... with untainted` stop matching and the call falls through to
`approval_invoker`: a human decides in Slack.

Rules
- Only the gate sets taint. No endpoint lets an agent (or the orchestrator) clear it.
- Taint is sticky for the life of the session. A new orchestrator run gets a new, clean session.
- Taint is content-blind: any successful call to a tainting tool taints, even a harmless
  page. The gate does not try to judge whether content is malicious; that is the point.
- Taint is marked BEFORE the tool result is returned to the agent, so no later call by
  an agent that has seen the content can be checked against a clean session.
- The transition (clean -> tainted) is its own audit event, `session_tainted`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

import asyncpg

from . import audit


@dataclass(frozen=True)
class SessionTaint:
    tainted: bool
    tainted_by: str | None = None


async def load(conn: asyncpg.Connection, session_id: str) -> SessionTaint | None:
    """Current taint of a session, or None if the session doesn't exist."""
    try:
        sid = uuid.UUID(session_id)
    except (TypeError, ValueError):
        return None
    row = await conn.fetchrow("SELECT tainted, tainted_by FROM sessions WHERE id = $1", sid)
    if row is None:
        return None
    return SessionTaint(bool(row["tainted"]), row["tainted_by"])


async def mark(conn: asyncpg.Connection, *, session_id: str, tool: str, agent_id: str,
               task_id: str | None = None, jti: str | None = None, via: str = "") -> bool:
    """Mark the session tainted by `tool`. Returns True only on the clean -> tainted
    transition (and writes one `session_tainted` audit event); False if it was already tainted.
    Raises on DB errors, so the caller fails closed (the content is never returned)."""
    changed = await conn.fetchval(
        """UPDATE sessions SET tainted = true, tainted_by = $2, tainted_at = now()
           WHERE id = $1 AND NOT tainted RETURNING id""",
        uuid.UUID(session_id), tool)
    if changed is None:
        return False
    await audit.append_event(
        conn, event_type="session_tainted", decision="info",
        reason=f"untrusted content from {tool}{via}; high-risk tools now need human approval",
        agent_id=agent_id, session_id=session_id, task_id=task_id, jti=jti, tool=tool,
        session_tainted=True)
    return True
