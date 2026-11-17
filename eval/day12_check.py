"""Day 12 done check, part "a redeploy keeps API-made grants", for Render (works locally too).

  python eval/day12_check.py setup  --target render   # register d12check-bot + a tool, grant it, call it
  (push something or click "Manual Deploy" on Render, wait until it is live)
  python eval/day12_check.py verify --target render   # the grant is still there and still works
  python eval/day12_check.py cleanup --target render  # remove the grant and the tool

The tool is a built-in mock (customer lookup), so no upstream credential is needed on Render.
The agent `d12check-bot` stays registered (agents are disabled, never deleted). Stdlib only.
Exit 0 = passed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gate import Gate, load_config  # noqa: E402

AGENT, TOOL = "d12check-bot", "d12check.lookup"
TOOL_ROW = {"name": TOOL, "description": "Day 12 redeploy check (built-in mock)", "risk_class": "read",
            "taints_session": False, "enabled": True, "upstream": {"kind": "builtin", "handler": "query_customers"},
            "args_schema": {"type": "object", "additionalProperties": False,
                            "properties": {"limit": {"type": "integer", "default": 1}}}}


def call_tool(gate: Gate) -> tuple[int, dict]:
    status, body, _ = gate.mint(AGENT, [TOOL], "day12 redeploy check")
    if status != 201:
        return status, body
    status, body, _ = gate.tool(body["access_token"], TOOL, {})
    return status, body


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("phase", choices=["setup", "verify", "cleanup"])
    ap.add_argument("--target", choices=["local", "render"], default="local")
    args = ap.parse_args()
    gate = Gate(load_config(args.target))
    gate.wait_healthy()
    fails = 0

    def check(name: str, ok: bool, detail: object = "") -> None:
        nonlocal fails
        fails += 0 if ok else 1
        print(f"{'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f"   [{detail}]"))

    if args.phase == "setup":
        status, body, _ = gate.admin("POST", "/agents", {"id": AGENT, "owner": "user:shiwin",
                                                         "display_name": "Day 12 check"})
        check("agent registered (or already there)", status in (201, 409), body)
        status, body, _ = gate.admin("POST", "/tools", TOOL_ROW)
        check("tool registered (or already there)", status in (201, 409), body)
        status, body, _ = gate.admin("POST", f"/agents/{AGENT}/grants", {"tool": TOOL})
        check("grant added (or already there)", status in (201, 409), body)
        status, body = call_tool(gate)
        check("the call is allowed", status == 200 and body.get("decision") == "allow", body)
        print("\nNow redeploy (Render: Manual Deploy), wait until it is live, then run: verify")
    elif args.phase == "verify":
        status, grants, _ = gate.admin("GET", f"/agents/{AGENT}/grants")
        items = grants.get("items", []) if isinstance(grants, dict) else grants
        check("the API-made grant is still in OpenFGA", status == 200 and any(
            g.get("tool") == TOOL and g.get("source") == "api" for g in items), grants)
        status, body = call_tool(gate)
        check("the call is still allowed", status == 200 and body.get("decision") == "allow", body)
    else:
        status, body, _ = gate.admin("DELETE", f"/agents/{AGENT}/grants?tool={TOOL}")
        check("grant removed", status in (200, 404), body)
        status, body = call_tool(gate)
        check("the next call is refused", status in (403,), body)
        status, body, _ = gate.admin("DELETE", f"/tools/{TOOL}")
        check("tool removed", status in (200, 404), body)
    status, chain, _ = gate.request("GET", "/audit/verify")
    check("audit chain valid", chain.get("valid") is True, chain)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
