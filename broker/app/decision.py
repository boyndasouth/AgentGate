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
) -> Decision:
    if tool not in token_scopes:
        return Decision("deny", f"tool '{tool}' is outside this task's token scopes")

    user, obj = f"agent:{agent_id}", f"tool:{tool}"
    # Always send every key: OpenFGA errors if a conditional tuple's parameter is missing.
    context = {"amount": float(amount), "session_tainted": bool(session_tainted), "host": host,
               "recipient_domain": recipient_domain, "payee": payee}

    try:
        if await fga.check(user, "can_invoke", obj, context):
            return Decision("allow", "policy: can_invoke")
        if await fga.check(user, "can_request_approval", obj, context):
            why = []
            if session_tainted:
                why.append(f"session tainted by {tainted_by}" if tainted_by else "session is tainted")
            if amount:
                why.append(f"amount {amount:g}")
            # Days 8-9 (G01, G04): would this call go through in a clean session with no amount?
            # If not, the allowlisted argument (recipient, payee) is (also) why a human is asked.
            # One extra check, on escalations of tools that have such an argument only.
            if allowlist_reason and not await fga.check(user, "can_invoke", obj,
                                                        {**context, "session_tainted": False, "amount": 0.0}):
                why.append(allowlist_reason)
            detail = f" ({', '.join(why)})" if why else ""
            return Decision("escalate", f"policy: needs human approval{detail}")
        if session_tainted and await fga.check(user, "can_request_approval", obj, {**context, "session_tainted": False}):
            # Only the taint stands in the way, and there's no approval path (read_web, G03).
            src = f" by {tainted_by}" if tainted_by else ""
            return Decision("deny", f"policy: session tainted{src}; host '{host or '?'}' is not on the "
                                    f"allowlist for '{tool}' in a tainted session")
        return Decision("deny", f"policy: agent '{agent_id}' has no grant on '{tool}'")
    except PolicyEngineError as exc:
        return Decision("deny", f"policy engine unavailable, failing closed: {exc}", policy_error=True)


async def may_hold_scope(fga: FGAClient, agent_id: str, tool: str) -> bool:
    """Token issuance: the agent may hold a scope if any path to the tool exists
    (direct or via approval). Checked in the most permissive context; the per-call
    check later applies the real amount and taint."""
    return await fga.check(
        f"agent:{agent_id}", "can_request_approval", f"tool:{tool}",
        {"amount": 0.0, "session_tainted": False, "host": "", "recipient_domain": "", "payee": ""},
    )
