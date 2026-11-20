"""Register the public sandbox for the /tour "Try it yourself" panel. Stdlib only.

Two agents (a customer-support agent and a DevOps agent) and their tools are added to a broker through
the admin API, exactly as a real user would. The tools are the broker's built-in mocks (nothing real is
touched), so this works on Render as well as locally. One approver, `demo-visitor`, is registered on the
risky sandbox tools ONLY. That is what makes the public page safe: the broker asks OpenFGA whether the
person deciding is an approver of that exact tool, so the visitor's Approve button cannot decide any
other approval, whatever the browser sends.

  py eval/seed_sandbox.py --target render      # the deployed broker (.env.render)
  py eval/seed_sandbox.py --target local       # the compose stack (.env)
  py eval/seed_sandbox.py --target render --remove

Safe to re-run: the sandbox's own grants, approvers and tools are removed and re-created each time.
Agents are never deleted (the broker has no delete), they just keep no grants after --remove.
"""

from __future__ import annotations

import argparse
import copy
import sys
import urllib.parse

from gate import Gate, load_config
from tour_scenarios import OWNER, devops_spec, support_spec

DEMO_APPROVER = "demo-visitor"
PREFIX = "sbx."


def sandbox_spec(spec: dict, agent: str, display: str) -> dict:
    """Turn a tour spec (http upstream) into a sandbox one: sbx.* tool names, built-in mock handlers."""
    spec = copy.deepcopy(spec)
    rename = {t["name"]: PREFIX + t["name"] for t in spec["tools"]}
    for t in spec["tools"]:
        handler = t["name"].replace(".", "_")
        t["name"] = rename[t["name"]]
        t["upstream"] = {"kind": "builtin", "handler": handler}
    spec["grants"] = [(rename[tool], mode, params) for tool, mode, params in spec["grants"]]
    spec["approvers"] = [rename[tool] for tool in spec["approvers"]]
    spec["agent"], spec["display"] = agent, display
    return spec


SPECS = [
    sandbox_spec(support_spec(""), "sandbox-support", "Support agent (sandbox)"),
    sandbox_spec(devops_spec(""), "sandbox-devops", "DevOps agent (sandbox)"),
]


def remove(g: Gate, admin: dict, spec: dict) -> None:
    status, body, _ = g.request("GET", f"/agents/{spec['agent']}/grants", None, admin)
    if status == 200:
        for gr in body.get("items") or []:
            if isinstance(gr, dict) and gr.get("source") == "api":
                g.request("DELETE", f"/agents/{spec['agent']}/grants?tool={urllib.parse.quote(gr['tool'])}", None, admin)
    for tool in spec["tools"]:
        for user in (OWNER, DEMO_APPROVER):
            g.request("DELETE", f"/tools/{tool['name']}/approvers/{user}", None, admin)
        g.request("DELETE", f"/tools/{tool['name']}", None, admin)


def need(cond: bool, what: str, got=None) -> None:
    if not cond:
        raise SystemExit(f"seed failed: {what}" + (f" (got: {got})" if got is not None else ""))


def seed(g: Gate, admin: dict, spec: dict) -> None:
    agent = spec["agent"]
    remove(g, admin, spec)
    status, body, _ = g.request("POST", "/agents", {"id": agent, "owner": OWNER, "display_name": spec["display"]}, admin)
    need(status in (201, 409), f"registering {agent}", (status, body))
    for tool in spec["tools"]:
        status, body, _ = g.request("POST", "/tools", {**tool, "enabled": True, "credential_ref": None}, admin)
        need(status == 201 and body.get("problem") is None, f"registering {tool['name']}", (status, body))
    for tool in spec["approvers"]:
        status, body, _ = g.request("POST", f"/tools/{tool}/approvers", {"user": DEMO_APPROVER}, admin)
        need(status == 201, f"approver for {tool}", (status, body))
    for tool, mode, params in spec["grants"]:
        payload = {"tool": tool, "mode": mode, **({"params": params} if params else {})}
        status, body, _ = g.request("POST", f"/agents/{agent}/grants", payload, admin)
        need(status == 201, f"granting {tool} ({mode})", (status, body))
    print(f"  {agent}: {len(spec['tools'])} tools, {len(spec['grants'])} grants, approver user:{DEMO_APPROVER}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", choices=("local", "render"), default="local")
    ap.add_argument("--remove", action="store_true", help="take the sandbox down (grants, approvers, tools)")
    args = ap.parse_args()
    g = Gate(load_config(args.target))
    admin = {"X-Admin-Key": g.cfg.admin_key}
    for spec in SPECS:
        if args.remove:
            remove(g, admin, spec)
            print(f"  {spec['agent']}: removed")
        else:
            seed(g, admin, spec)
    print("sandbox is down" if args.remove else "sandbox is ready: set AGENTGATE_SANDBOX=1 in Vercel to show it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
