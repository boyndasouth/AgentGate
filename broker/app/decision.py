"""Decision engine: maps two OpenFGA checks to allow / escalate / deny.

  can_invoke            true -> allow
  can_request_approval  true -> escalate (a human decides, Day 4: Slack)
  neither                    -> deny

The token's scope list is checked first: a call outside the task's scopes is
denied without asking OpenFGA. If OpenFGA errors, the gate fails closed (deny).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .fga import FGAClient, PolicyEngineError

Outcome = Literal["allow", "escalate", "deny"]


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reason: str
    policy_error: bool = False


async def decide(
    fga: FGAClient,
    *,
    agent_id: str,
    tool: str,
    token_scopes: frozenset[str],
    amount: float,
    session_tainted: bool,
    tainted_by: str | None = None,
    host: str = "",
    recipient_domain: str = "",
    payee: str = "",
    allowlist_reason: str | None = None,
    invoice_matches: bool = False,
    invoice_reason: str | None = None,
) -> Decision:
    """`agent_id` is whose access is judged: for a delegated call (Day 10), the principal."""
    if tool not in token_scopes:
        return Decision("deny", f"tool '{tool}' is outside this task's token scopes")

    user, obj = f"agent:{agent_id}", f"tool:{tool}"
    # Always send every key: OpenFGA errors if a conditional tuple's parameter is missing.
    context = {"amount": float(amount), "session_tainted": bool(session_tainted), "host": host,
               "recipient_domain": recipient_domain, "payee": payee, "invoice_matches": bool(invoice_matches)}

    try:
        if await fga.check(user, "can_invoke", obj, context):
            return Decision("allow", "policy: can_invoke")
        if await fga.check(user, "can_request_approval", obj, context):
            why = []
            if session_tainted:
                why.append(f"session tainted by {tainted_by}" if tainted_by else "session is tainted")
            if amount:
                why.append(f"amount {amount:g}")
            # Days 8-9 (G01, G04): would this call go through in a clean session with no amount
            # (and a matching invoice)? If not, the allowlisted argument (recipient, payee) is
            # (also) why a human is asked. One extra check, on escalations of such tools only.
            if allowlist_reason and not await fga.check(
                    user, "can_invoke", obj,
                    {**context, "session_tainted": False, "amount": 0.0, "invoice_matches": True}):
                why.append(allowlist_reason)
            if invoice_reason:      # Day 10 (G05): no open invoice matches this payment
                why.append(invoice_reason)
            detail = f" ({', '.join(why)})" if why else ""
            return Decision("escalate", f"policy: needs human approval{detail}")
        if session_tainted and await fga.check(user, "can_request_approval", obj, {**context, "session_tainted": False}):
            # Only the taint stands in the way, and there's no approval path (read_web, G03).
            src = f" by {tainted_by}" if tainted_by else ""
            if not host:    # Day 12: a clean-session-only grant on a tool that has no URL
                return Decision("deny", f"policy: session tainted{src}; '{tool}' may only run in a clean "
                                        "session and has no approval path")
            return Decision("deny", f"policy: session tainted{src}; host '{host or '?'}' is not on the "
                                    f"allowlist for '{tool}' in a tainted session")
        return Decision("deny", f"policy: agent '{agent_id}' has no grant on '{tool}'")
    except PolicyEngineError as exc:
        return Decision("deny", f"policy engine unavailable, failing closed: {exc}", policy_error=True)


async def may_hold_scope(fga: FGAClient, agent_id: str, tool: str) -> bool:
    """Token issuance: the agent may hold a scope if any path to the tool exists
    (direct or via approval). Checked in the most permissive context; the per-call
    check later applies the real amount and taint."""
    if await fga.check(
        f"agent:{agent_id}", "can_request_approval", f"tool:{tool}",
        {"amount": 0.0, "session_tainted": False, "host": "", "recipient_domain": "", "payee": "",
         "invoice_matches": False},
    ):
        return True
    # Day 12: a direct grant whose condition can't hold in that empty context (an allowlisted
    # recipient, a payee with an invoice) is still a path to the tool, even with no approval grant
    # next to it. The stored tuple is the evidence; each call is still checked with real values.
    return bool(await fga.read({"user": f"agent:{agent_id}", "relation": "direct_invoker", "object": f"tool:{tool}"}))
