"""The gate: one function that decides and runs a single tool call.

Until Day 13 this lived inside the `POST /tools/{name}` handler. Day 14 moves it here so the HTTP
route and the MCP gateway (`/mcp`, mcp_gateway.py) share ONE implementation: whatever the
transport, a call is judged by the same steps in the same order, and writes the same audit rows.

    run_gate(state, conn, claims, name, raw_args) -> (http_status, body)

`claims` come from a verified AgentGate token (the caller decoded it). The result is the HTTP
status the route returns and its body, a ToolResult, or a plain dict for the early 401s. The MCP
gateway maps that same pair to an MCP tool result.

Steps, in order (each early exit writes its own audit row):
  taint loaded -> revocation / kill switch -> session known -> tool known, enabled, valid ->
  arguments valid -> policy context built -> delegation chain live -> invoice matched ->
  OpenFGA decision -> deny | escalate (approval row, Slack) | allow (run, settle, taint).
"""

from __future__ import annotations

from typing import Any

import asyncpg
import msgspec
from litestar.datastructures import State

from . import audit, delegation, invoices, registry, taint, upstream
from .decision import decide
from .registry import REGISTRY, ArgsError, ContextError
from .tokens import AgentClaims, TokenError, check_not_revoked
from .fga import PolicyEngineError


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


async def run_gate(state: State, conn: asyncpg.Connection, claims: AgentClaims, name: str,
                   raw_args: dict[str, Any]) -> tuple[int, Any]:
    """Decide and, if allowed, run one call. Returns (http status, body); never raises for a
    policy outcome. 200 = allow (result included), 202 = escalate (pending human), 403 = deny."""
    settings = state.settings

    # 2. Session taint (Day 5): set by the gate, never by the agent. Loaded first so that
    #    every audit row for this call, even an early deny, records the taint it was judged under.
    st = await taint.load(conn, claims.session_id)
    # Day 10: a delegated call also carries the taint of every session its grants came from.
    st = await delegation.effective_taint(conn, claims, st)
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
        return 401, {"decision": "deny", "reason": str(exc), "tool": name, "audit_id": ev["id"],
                     "session_tainted": tainted}

    # 4. Known session, known tool, valid arguments.
    if st is None:
        ev = await record("deny", "unknown session")
        return 401, ToolResult(decision="deny", reason="unknown session", tool=name, audit_id=ev["id"])
    #    Day 11: the tool comes from the registry table. Unknown, disabled and misconfigured
    #    tools are refused here, before OpenFGA is asked.
    tool = await REGISTRY.get(conn, name) if registry.TOOL_NAME.fullmatch(name) else None
    if tool is None:
        ev = await record("deny", f"unknown tool '{name[:64]}'")
        return 404, ToolResult(decision="deny", reason=f"unknown tool '{name[:64]}'", tool=name,
                               audit_id=ev["id"], session_tainted=tainted)
    args_hash = audit.args_digest(settings.args_hmac_key, raw_args)
    why = tool.unavailable_reason()
    if why is not None:
        ev = await record("deny", why, args_hash=args_hash)
        return 403, ToolResult(decision="deny", reason=why, tool=name, audit_id=ev["id"],
                               session_tainted=tainted)
    try:
        args = registry.validate(tool, raw_args)
    except ArgsError as exc:
        ev = await record("deny", f"invalid arguments: {exc}", args_hash=args_hash)
        return 422, ToolResult(decision="deny", reason=f"invalid arguments: {exc}", tool=name,
                               audit_id=ev["id"], session_tainted=tainted)
    try:
        ctx = registry.policy_inputs(tool, args)     # built from the row's context_map
    except ContextError as exc:
        why = f"can't build the policy context, failing closed: {exc}"
        ev = await record("deny", why, args_hash=args_hash)
        return 403, ToolResult(decision="deny", reason=why, tool=name, audit_id=ev["id"],
                               session_tainted=tainted)

    # 4b. Day 10: a delegated token works only while every hop is live and covers this tool.
    acting = ""
    if claims.delegated:
        acting = f" (as agent:{claims.principal} via delegation {' -> '.join(d[:8] for d in claims.delegation_ids)})"
        if name in claims.scopes:
            try:
                why = await delegation.live(conn, state.fga, claims, name)
            except PolicyEngineError as exc:
                why = f"policy engine unavailable, failing closed: {exc}"
                ev = await record("deny", why, args_hash=args_hash)
                return 503, ToolResult(decision="deny", reason=why, tool=name, audit_id=ev["id"],
                                       session_tainted=tainted)
            if why is not None:
                ev = await record("deny", f"{why}{acting}", args_hash=args_hash)
                return 403, ToolResult(decision="deny", reason=why, tool=name, audit_id=ev["id"],
                                       session_tainted=tainted)

    # 4c. Day 10 (G05): does the payment match an open invoice? OpenFGA gets the answer as context.
    inv = invoices.Match(False)
    if ctx.invoice_id is not None:
        inv = await invoices.match(conn, ctx.invoice_id, ctx.payee, ctx.amount)

    # 5. Policy decision, with the session's taint as OpenFGA context. A delegated call is judged
    #    AS its principal: the delegate can never do more than the agent it acts for.
    decision = await decide(state.fga, agent_id=claims.principal, tool=name, token_scopes=claims.scopes,
                            amount=ctx.amount, session_tainted=st.tainted,
                            tainted_by=st.tainted_by, host=ctx.host,
                            recipient_domain=ctx.recipient_domain, payee=ctx.payee,
                            allowlist_reason=ctx.allowlist_reason,
                            invoice_matches=inv.ok, invoice_reason=inv.why)
    if acting:
        decision = type(decision)(decision.outcome, decision.reason + acting, decision.policy_error)

    if decision.outcome == "deny":
        ev = await record("deny", decision.reason, args_hash=args_hash)
        return (503 if decision.policy_error else 403,
                ToolResult(decision="deny", reason=decision.reason, tool=name, audit_id=ev["id"],
                           session_tainted=tainted))

    if decision.outcome == "escalate":
        # Raw args are kept on the approval row only while pending: the broker replays the
        # call itself on Approve, so the agent never re-sends it.
        row = await state.approvals.create(
            conn, agent_id=claims.agent_id, session_id=claims.session_id, task_id=claims.task_id,
            tool=name, args=raw_args, args_hash=args_hash, reason=decision.reason, session_tainted=tainted,
            principal=claims.principal if claims.delegated else None,
            delegation_ids=list(claims.delegation_ids) or None)
        ev = await record("escalate", f"{decision.reason}; approval {row['id']}", args_hash=args_hash)
        await state.approvals.announce(conn, row, ev["id"])
        return 202, ToolResult(decision="escalate", reason=decision.reason, tool=name,
                               audit_id=ev["id"], approval_id=str(row["id"]), status="pending",
                               expires_at=row["expires_at"].isoformat(), session_tainted=tainted)

    # 6. Allow: run the tool (the broker, not the agent, holds any real API keys).
    #    Day 10: a payment allowed against an invoice settles it in the same transaction, so two
    #    calls racing to pay the same invoice can't both go through.
    #    Day 12: an http upstream is called with the credential the broker holds; the agent gets
    #    the upstream's status and body, scrubbed of that credential.
    try:
        async with conn.transaction():
            if inv.ok and not await invoices.settle(conn, ctx.invoice_id, ctx.payee, ctx.amount):
                raise ValueError("the invoice was paid by another call a moment ago")
            result = await registry.run(tool, args)
            if inv.ok:
                await invoices.record_tx(conn, ctx.invoice_id, registry.tx_id_of(result))
    except ValueError as exc:
        ev = await record("allow", f"{decision.reason}; tool rejected input: {exc}", args_hash=args_hash)
        return 400, ToolResult(decision="allow", reason=f"tool error: {exc}", tool=name,
                               audit_id=ev["id"], session_tainted=tainted)
    except upstream.UpstreamError as exc:
        # Allowed, but no usable answer. Nothing from the upstream reaches the agent, so the
        # session isn't tainted by it. The text is written by the broker, never copied.
        ev = await record("allow", f"{decision.reason}; upstream error: {exc}", args_hash=args_hash)
        return 502, ToolResult(decision="allow", reason=f"upstream error: {exc}", tool=name,
                               audit_id=ev["id"], session_tainted=tainted)
    # The call row records the taint the decision was made under (before this call).
    ev = await record("allow", decision.reason, args_hash=args_hash)

    # 7. Day 5: untrusted content taints the session BEFORE the agent sees it. If marking
    #    fails, this raises and the content is never returned (fail closed).
    if tool.taints:
        await taint.mark(conn, session_id=claims.session_id, tool=name, agent_id=claims.agent_id,
                         task_id=claims.task_id, jti=claims.jti)
        tainted = True
    # Response: session_tainted is the session's state AFTER this call.
    return 200, ToolResult(decision="allow", reason=decision.reason, tool=name, audit_id=ev["id"],
                           result=result, session_tainted=tainted)
