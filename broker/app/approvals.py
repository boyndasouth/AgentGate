"""Human approvals for escalated tool calls (Day 4).

Lifecycle of one approval row:

    pending --Approve--> approved   (the broker replays the stored call; result kept for the agent)
            --Deny-----> denied
            --TTL------> expired    (timeout counts as deny)
            --agent----> expired    (agent gave up waiting and cancelled)

Rules this module enforces:
- One decision per approval: every transition is `UPDATE ... WHERE status = 'pending'`,
  so a double click, or Approve and Deny racing, can only resolve it once.
- No decisions after expiry: the claim also requires `now() <= expires_at`.
- Who may decide is policy, not config: the Slack user is mapped to `user:<name>`, then
  OpenFGA must say that user is an `approver` of this tool.
- The kill switch still wins: Approve on a disabled agent's call is turned into a deny.
  Day 10: for a delegated call, every agent in the chain must still be active and no delegation
  in it revoked, or Approve becomes a deny.
- Raw args live only while pending; every resolution sets `args = NULL`.
- Every resolution (and every refused click) is a row in the hash-chained audit log,
  with the approver's identity in the `approver` column.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

import asyncpg

from . import audit, invoices, taint
from .fga import FGAClient, PolicyEngineError
from .tools import TOOLS, parse_args

log = logging.getLogger("agentgate.approvals")

_MAX_FIELD = 200      # chars per argument value shown to a human
_MAX_FIELDS = 8


class Notifier(Protocol):
    """Implemented by app.slack.SlackApprovals. Kept abstract so Slack can be off."""

    async def post(self, row: dict) -> tuple[str, str] | None: ...
    async def update(self, row: dict) -> None: ...


class ApprovalError(Exception):
    """A decision that can't be applied. `status` is the HTTP status the API should use."""

    def __init__(self, message: str, status: int = 409) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Approver:
    user: str      # AgentGate user name, e.g. 'shiwin' (OpenFGA: user:shiwin)
    via: str       # 'slack:U07ABC123' | 'admin-ui:auth0|abc' | 'admin-api'

    @property
    def label(self) -> str:
        return f"user:{self.user} via {self.via}"


def summarize_args(tool: str, args: dict | None) -> list[tuple[str, str]]:
    """What the human sees: each argument, truncated. Shown to the approver only;
    the audit log keeps the HMAC of the args, never the values."""
    if not args:
        return []
    # jsonb reorders keys; show them in the tool's own argument order.
    order = getattr(TOOLS[tool].args_type, "__struct_fields__", ()) if tool in TOOLS else ()
    keys = [k for k in order if k in args] + [k for k in args if k not in order]
    out = []
    for key, value in [(k, args[k]) for k in keys][:_MAX_FIELDS]:
        text = value if isinstance(value, str) else repr(value)
        text = " ".join(str(text).split())   # collapse newlines so one field stays one line
        out.append((key, text if len(text) <= _MAX_FIELD else text[: _MAX_FIELD - 1] + "…"))
    return out


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _row(rec: asyncpg.Record | None) -> dict | None:
    return dict(rec) if rec is not None else None


class ApprovalService:
    def __init__(self, pool: asyncpg.Pool, fga: FGAClient, *, ttl_seconds: int,
                 notifier: Notifier | None = None) -> None:
        self.pool = pool
        self.fga = fga
        self.ttl_seconds = ttl_seconds
        self.notifier = notifier

    # ------------------------------------------------------------------ create

    async def create(self, conn: asyncpg.Connection, *, agent_id: str, session_id: str, task_id: str,
                     tool: str, args: dict, args_hash: str, reason: str, session_tainted: bool,
                     principal: str | None = None, delegation_ids: list[str] | None = None) -> dict:
        approval_id = uuid.uuid4()
        rec = await conn.fetchrow(
            """INSERT INTO approvals (id, agent_id, session_id, task_id, tool, args, args_hash, reason,
                                      session_tainted, expires_at, principal, delegation_ids)
               VALUES ($1, $2, $3::uuid, $4::uuid, $5, $6, $7, $8, $9, now() + make_interval(secs => $10),
                       $11, $12::uuid[])
               RETURNING *""",
            approval_id, agent_id, session_id, task_id, tool, args, args_hash, reason,
            session_tainted, float(self.ttl_seconds), principal,
            [uuid.UUID(d) for d in delegation_ids] if delegation_ids else None)
        return dict(rec)

    async def announce(self, conn: asyncpg.Connection, row: dict, audit_id: int) -> bool:
        """Post the Approve/Deny message. Best effort: if Slack is off or fails, the
        approval stays pending (decidable via the admin API) and times out as a deny."""
        if self.notifier is None:
            return False
        try:
            posted = await self.notifier.post({**row, "audit_id": audit_id})
        except Exception:   # noqa: BLE001 - never let Slack break the gate
            log.exception("Slack post failed for approval %s", row["id"])
            return False
        if posted:
            channel, ts = posted
            await conn.execute("UPDATE approvals SET slack_channel = $2, slack_ts = $3 WHERE id = $1",
                               row["id"], channel, ts)
        return bool(posted)

    # ------------------------------------------------------------------ read

    async def get(self, conn: asyncpg.Connection, approval_id: uuid.UUID) -> dict | None:
        row = _row(await conn.fetchrow("SELECT * FROM approvals WHERE id = $1", approval_id))
        if row and row["status"] == "pending" and row["expires_at"] <= _now():
            row = await self._expire(conn, row, via="timeout",
                                     reason=f"no human decision within {self.ttl_seconds}s; timeout counts as deny")
        return row

    async def list_recent(self, conn: asyncpg.Connection, status: str | None, limit: int = 50) -> list[dict]:
        await self.expire_overdue(conn)
        rows = await conn.fetch(
            """SELECT * FROM approvals WHERE ($1::text IS NULL OR status = $1)
               ORDER BY created_at DESC LIMIT $2""", status, limit)
        return [dict(r) for r in rows]

    async def expire_overdue(self, conn: asyncpg.Connection) -> int:
        """Expire every overdue pending approval (startup sweep, admin list)."""
        overdue = await conn.fetch(
            "SELECT * FROM approvals WHERE status = 'pending' AND expires_at <= now() ORDER BY created_at")
        for rec in overdue:
            await self._expire(conn, dict(rec), via="timeout",
                               reason="no human decision before expiry; timeout counts as deny")
        return len(overdue)

    # ------------------------------------------------------------------ agent side

    async def cancel(self, conn: asyncpg.Connection, row: dict) -> dict:
        """The waiting agent gave up (its own timeout). Close the approval so a late
        click can't run a call the agent already reported as refused."""
        if row["status"] != "pending":
            return row
        return await self._expire(conn, row, via="agent-cancel",
                                  reason="agent stopped waiting; counts as deny")

    # ------------------------------------------------------------------ human side

    async def decide(self, approval_id: uuid.UUID, *, approve: bool, approver: Approver) -> dict:
        """Apply one human decision. Returns the resolved row. Raises ApprovalError."""
        async with self.pool.acquire() as conn:
            row = await self.get(conn, approval_id)          # also expires it if overdue
            if row is None:
                raise ApprovalError("unknown approval", 404)
            if row["status"] != "pending":
                raise ApprovalError(f"already {row['status']}"
                                    + (f" by {row['approver']}" if row.get("approver") else ""))

            # Who may decide is policy: OpenFGA `approver` relation on the tool.
            try:
                allowed = await self.fga.check(f"user:{approver.user}", "approver", f"tool:{row['tool']}",
                                               {"amount": 0.0, "session_tainted": False})
            except PolicyEngineError as exc:
                raise ApprovalError(f"policy engine unavailable, failing closed: {exc}", 503) from exc
            if not allowed:
                await audit.append_event(
                    conn, event_type="approval_refused", decision="info",
                    reason=f"{approver.label} is not an approver of {row['tool']}; approval {row['id']} still pending",
                    agent_id=row["agent_id"], session_id=str(row["session_id"]), task_id=str(row["task_id"]),
                    tool=row["tool"], args_hash=row["args_hash"], approver=approver.label,
                    session_tainted=row["session_tainted"])
                raise ApprovalError(f"user:{approver.user} is not an approver of {row['tool']}", 403)

            note = ""
            if approve:
                chain = list({row["agent_id"], row.get("principal") or row["agent_id"]})
                off = await conn.fetchval(
                    "SELECT array_agg(id ORDER BY id) FROM agents WHERE id = ANY($1::text[]) AND status <> 'active'",
                    chain)
                if off:
                    approve, note = False, f"agent '{off[0]}' was disabled while pending (kill switch)"
                elif row.get("delegation_ids") and await conn.fetchval(
                        "SELECT EXISTS (SELECT 1 FROM delegations WHERE id = ANY($1::uuid[]) AND revoked_at IS NOT NULL)",
                        row["delegation_ids"]):
                    approve, note = False, "a delegation in the chain was revoked while pending"

            new_status = "approved" if approve else "denied"
            claimed = _row(await conn.fetchrow(
                """UPDATE approvals SET status = $2, approver = $3, resolved_via = $4, resolved_at = now()
                   WHERE id = $1 AND status = 'pending' AND now() <= expires_at
                   RETURNING *""",
                row["id"], new_status, approver.label, approver.via))
            if claimed is None:     # lost a race with another click or the TTL
                latest = await self.get(conn, row["id"])
                raise ApprovalError(f"already {latest['status'] if latest else 'gone'}")

            if approve:
                result, outcome = await self._run(conn, claimed)
                reason = f"approved by {approver.label}; {outcome}; approval {claimed['id']}"
            else:
                result = None
                reason = f"denied by {approver.label}" + (f" ({note})" if note else "") + f"; approval {claimed['id']}"

            claimed = dict(await conn.fetchrow(
                "UPDATE approvals SET args = NULL, result = $2 WHERE id = $1 RETURNING *", claimed["id"], result))
            await audit.append_event(
                conn, event_type="approval_resolved", decision="allow" if approve else "deny", reason=reason,
                agent_id=claimed["agent_id"], session_id=str(claimed["session_id"]),
                task_id=str(claimed["task_id"]), tool=claimed["tool"], args_hash=claimed["args_hash"],
                approver=approver.label, session_tainted=claimed["session_tainted"])
        await self._notify(claimed)
        return claimed

    # ------------------------------------------------------------------ internals

    async def _run(self, conn: asyncpg.Connection, row: dict) -> tuple[dict, str]:
        """Replay the approved call. The broker, not the agent, executes it."""
        tool = TOOLS[row["tool"]]
        try:
            parsed = parse_args(tool, row["args"])
            async with conn.transaction():
                # Day 10: an approved payment that names an open, matching invoice settles it, so
                # it can't be paid again alone. (A human may approve paying without one.)
                inv = getattr(parsed, tool.invoice_field, "") if tool.invoice_field else ""
                settled = bool(inv) and await invoices.settle(conn, inv, getattr(parsed, tool.payee_field),
                                                              getattr(parsed, tool.amount_field))
                result = await tool.run(parsed)
                if settled:
                    await invoices.record_tx(conn, inv, result.get("tx_id", ""))
        except Exception as exc:   # noqa: BLE001 - report tool failure to the agent, keep the chain going
            return {"error": str(exc)}, f"tool failed: {exc}"
        # Day 5: an approved call to a tainting tool still taints the session before the
        # polling agent gets the content. (No approvable tool taints today; kept for parity
        # with the gate so a future policy change can't open a hole.)
        if tool.taints:
            await taint.mark(conn, session_id=str(row["session_id"]), tool=row["tool"],
                             agent_id=row["agent_id"], task_id=str(row["task_id"]),
                             via=f" (approved call {row['id']})")
        return result, f"tool ran: {result.get('status', 'ok')}"

    async def _expire(self, conn: asyncpg.Connection, row: dict, *, via: str, reason: str) -> dict:
        expired = _row(await conn.fetchrow(
            """UPDATE approvals SET status = 'expired', resolved_via = $2, resolved_at = now(), args = NULL
               WHERE id = $1 AND status = 'pending' RETURNING *""", row["id"], via))
        if expired is None:     # someone else resolved it first
            return dict(await conn.fetchrow("SELECT * FROM approvals WHERE id = $1", row["id"]))
        await audit.append_event(
            conn, event_type="approval_resolved", decision="deny", reason=f"{reason}; approval {expired['id']}",
            agent_id=expired["agent_id"], session_id=str(expired["session_id"]),
            task_id=str(expired["task_id"]), tool=expired["tool"], args_hash=expired["args_hash"],
            approver=None, session_tainted=expired["session_tainted"])
        await self._notify(expired)
        return expired

    async def _notify(self, row: dict) -> None:
        if self.notifier is None or not row.get("slack_ts"):
            return
        try:
            await self.notifier.update(row)
        except Exception:   # noqa: BLE001
            log.exception("Slack update failed for approval %s", row["id"])


def agent_view(row: dict) -> tuple[int, dict[str, Any]]:
    """What a polling agent gets: the same shape as a /tools response.
    pending -> 202 escalate, approved -> 200 allow + result, denied/expired -> 403 deny."""
    base: dict[str, Any] = {
        "tool": row["tool"], "approval_id": str(row["id"]), "status": row["status"],
        "expires_at": row["expires_at"].isoformat(),
    }
    if row["status"] == "pending":
        return 202, {**base, "decision": "escalate", "reason": f"waiting for a human: {row['reason']}"}
    if row["status"] == "approved":
        return 200, {**base, "decision": "allow", "reason": f"approved by {row['approver']}",
                     "approver": row["approver"], "result": row["result"]}
    if row["status"] == "denied":
        return 403, {**base, "decision": "deny", "reason": f"denied by {row['approver']}",
                     "approver": row["approver"]}
    why = "the agent stopped waiting" if row.get("resolved_via") == "agent-cancel" else "no human decision in time"
    return 403, {**base, "decision": "deny", "reason": f"approval expired ({why}); timeout counts as deny"}


def admin_view(row: dict) -> dict[str, Any]:
    """Admin / Day 6 UI view: the args summary a human needs, never the raw args or result."""
    return {
        "id": str(row["id"]), "agent_id": row["agent_id"], "session_id": str(row["session_id"]),
        "task_id": str(row["task_id"]), "tool": row["tool"], "reason": row["reason"],
        "status": row["status"], "approver": row["approver"], "resolved_via": row.get("resolved_via"),
        "session_tainted": row.get("session_tainted"),
        "summary": dict(summarize_args(row["tool"], row.get("args"))),
        "created_at": row["created_at"].isoformat(), "expires_at": row["expires_at"].isoformat(),
        "resolved_at": row["resolved_at"].isoformat() if row.get("resolved_at") else None,
    }
