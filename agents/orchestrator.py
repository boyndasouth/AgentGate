"""Simple orchestrator: runs a fixed plan of agent steps in ONE AgentGate session.

- Holds the orchestrator key; agents never do.
- Mints a fresh 10-minute token per agent per step, scoped to that agent's tools.
- Hands each step's output to the next step ({previous} in the task text).
- Stops the hand-off chain as soon as AgentGate escalates or denies anything;
  that decision comes from the gate's responses, not from what the model claims.

Usage (inside the agents container, see scripts/run_agents.ps1):
  python -m agents.orchestrator pay          # $40 invoice -> allow
  python -m agents.orchestrator big          # $5,000 -> escalate (pending until Day 4 Slack)
  python -m agents.orchestrator brief        # researcher -> mailer hand-off
  python -m agents.orchestrator scope        # researcher asks for transfer_funds -> refused at issuance
  python -m agents.orchestrator --agent finance 'Pay $12 to Acme Supplies'
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from dataclasses import dataclass

from pydantic_ai.exceptions import UsageLimitExceeded

from .gate_client import GateClient
from .team import AGENTS, LIMITS, SCOPES, Deps


@dataclass
class Step:
    agent: str
    task: str                       # may contain {previous}
    scopes: list[str] | None = None  # override (used by the 'scope' scenario)


SCENARIOS: dict[str, list[Step]] = {
    "pay": [Step("finance", "Pay invoice INV-1042: $40.00 to Acme Supplies.")],
    "big": [Step("finance", "Pay invoice INV-2077: $5,000.00 to Northwind Consulting.")],
    "brief": [
        Step("researcher", "Read https://example.com/agent-security and summarise it in 3 short bullet points."),
        Step("mailer", "Email this research brief to shiwin@example.com with the subject 'Research brief':\n\n{previous}"),
    ],
    # The researcher has no path to transfer_funds in OpenFGA, so AgentGate refuses the token itself.
    "scope": [Step("researcher", "Pay invoice INV-1042: $40.00 to Acme Supplies.", scopes=["transfer_funds"])],
}


def _env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        sys.exit(f"missing env var {name}")
    return v


async def run_plan(steps: list[Step], gate: GateClient) -> int:
    print(f"AgentGate: {gate.base_url}")
    print(f"health: {await gate.health()}")   # also wakes a sleeping Render instance

    session_id: str | None = None
    previous = ""
    outcome = 0

    for i, step in enumerate(steps, 1):
        task = step.task.format(previous=previous)
        scopes = step.scopes or SCOPES[step.agent]
        print(f"\n=== step {i}: {step.agent}  scopes={scopes}")

        try:
            token = await gate.mint_token(step.agent, task, scopes, session_id)
        except PermissionError as e:
            print(f"  token REFUSED: {e}")
            outcome = 2
            break
        session_id = token.session_id
        print(f"  token jti={token.jti} session={token.session_id} expires={token.expires_at}")

        deps = Deps(gate=gate, token=token)
        try:
            result = await AGENTS[step.agent].run(task, deps=deps, usage_limits=LIMITS)
            reply = result.output
        except UsageLimitExceeded as e:
            reply = f"(stopped: {e})"

        for c in deps.calls:
            print(f"  gate: {c.tool:<16} {c.decision:<9} audit_id={c.audit_id}  {c.reason}")
        print(f"  {step.agent} says: {reply}")

        blocked = [c for c in deps.calls if c.decision != "allow"]
        if not deps.calls:
            print("  (agent made no tool calls)")
        if blocked:
            outcome = 1
            print(f"  hand-off stopped: {blocked[0].tool} -> {blocked[0].decision}")
            break
        previous = reply

    r = await gate.http.get("/audit/verify")
    print(f"\nsession={session_id}\naudit/verify: {r.json()}")
    return outcome


async def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("arg", nargs="?", help=f"scenario ({', '.join(SCENARIOS)}) or, with --agent, the task text")
    p.add_argument("--agent", choices=sorted(AGENTS))
    a = p.parse_args()

    if a.agent:
        if not a.arg:
            p.error("--agent needs a task")
        steps = [Step(a.agent, a.arg)]
    elif a.arg in SCENARIOS:
        steps = SCENARIOS[a.arg]
    else:
        p.error(f"unknown scenario {a.arg!r}; pick one of {', '.join(SCENARIOS)}")

    async with GateClient(_env("AGENTGATE_URL"), _env("AGENTGATE_ORCHESTRATOR_KEY")) as gate:
        return await run_plan(steps, gate)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
