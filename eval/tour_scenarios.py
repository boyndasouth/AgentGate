"""Extra scenarios for the /tour page: other kinds of agents behind the same gate.

eval/export_tour.py records the finance-team demo. This module records two more, with agents and tools
that are NOT part of the broker's code: each one is registered through the admin API (agent, tools,
grants, approvers), exactly as a real user would, and then plays scripted calls (no LLM) against the
real gate. Nothing in the broker changes. Tools forward to the compose `mock-upstream` service, so this
only runs against the local stack.

  support   a customer-support agent: looks up orders, replies to customers, reads tickets (outsider text),
            asks for refunds. A poisoned ticket tells it to refund and email data out.
  devops    a repo-automation agent: comments on issues, reads issues (outsider text), deletes branches.
            A poisoned issue tells it to delete a release branch.

Every scenario asserts the outcome it expects at each key step and exits through SystemExit if the gate
answers differently, so the page never shows a result the gate did not give. Re-running is safe: the
scenario's own grants, approvers and tools are removed first (silently), the agent row stays (agents are
never deleted).
"""

from __future__ import annotations

import urllib.parse

from export_tour import APPROVER, Recorder, approval_view, newest_id

OWNER = APPROVER                       # 'shiwin': owner of the agents, approver of the risky tools
CREDENTIAL = "UPSTREAM_MOCK_TOKEN"     # the env var the broker holds (docker-compose sets it)


def _schema(props: dict, required: list[str]) -> dict:
    return {"type": "object", "additionalProperties": False, "required": required, "properties": props}


def _str(n: int = 64) -> dict:
    return {"type": "string", "maxLength": n}


MODE_WORDS = {
    "direct": "may call it on its own",
    "direct_if_untainted": "may call it on its own, but only while the session is clean",
    "direct_allowlisted_recipient": "may call it on its own, but only in a clean session and only to allowlisted domains",
    "approval": "every call goes to a human",
}


# ----------------------------------------------------------------------------- the two agents


def support_spec(mock: str) -> dict:
    def http(method: str, path: str) -> dict:
        return {"kind": "http", "method": method, "url": mock + path}

    return {
        "agent": "tour-support", "display": "Support agent (tour)",
        "tools": [
            {"name": "crm.lookup_order", "description": "Look up an order in the CRM.", "risk_class": "read",
             "taints_session": False, "context_map": {},
             "args_schema": _schema({"order_id": _str(32)}, ["order_id"]),
             "upstream": http("GET", "/crm/orders/{order_id}")},
            {"name": "crm.read_ticket", "description": "Read a customer's ticket (text written by the customer).",
             "risk_class": "read", "taints_session": True, "context_map": {},
             "args_schema": _schema({"ticket_id": _str(32)}, ["ticket_id"]),
             "upstream": http("GET", "/crm/tickets/{ticket_id}")},
            {"name": "crm.refund", "description": "Refund an order.", "risk_class": "money",
             "taints_session": False, "context_map": {"amount": "amount"},
             "args_schema": _schema({"order_id": _str(32), "amount": {"type": "number"}}, ["order_id", "amount"]),
             "upstream": http("POST", "/crm/refunds")},
            {"name": "support.reply", "description": "Email a reply to a customer.", "risk_class": "egress",
             "taints_session": False, "context_map": {"recipient": "to"},
             "args_schema": _schema({"to": _str(254), "subject": _str(200), "body": _str(4000)}, ["to", "subject", "body"]),
             "upstream": http("POST", "/email/send")},
        ],
        "grants": [
            ("crm.lookup_order", "direct", None),
            ("crm.read_ticket", "direct", None),
            ("support.reply", "direct_allowlisted_recipient", {"allowed_recipient_domains": ["customers.example"]}),
            ("support.reply", "approval", None),
            ("crm.refund", "approval", None),
        ],
        "approvers": ["support.reply", "crm.refund"],
    }


def devops_spec(mock: str) -> dict:
    def http(method: str, path: str) -> dict:
        return {"kind": "http", "method": method, "url": mock + path}

    return {
        "agent": "tour-devops", "display": "DevOps agent (tour)",
        "tools": [
            {"name": "repo.read_issue", "description": "Read an issue (text written by outsiders).",
             "risk_class": "read", "taints_session": True, "context_map": {},
             "args_schema": _schema({"repo": _str(64), "number": {"type": "integer"}}, ["repo", "number"]),
             "upstream": http("GET", "/repos/{repo}/issues/{number}")},
            {"name": "repo.comment", "description": "Comment on an issue.", "risk_class": "write",
             "taints_session": False, "context_map": {},
             "args_schema": _schema({"repo": _str(64), "number": {"type": "integer"}, "body": _str(2000)},
                                    ["repo", "number", "body"]),
             "upstream": http("POST", "/repos/{repo}/issues/{number}/comments")},
            {"name": "repo.delete_branch", "description": "Delete a branch.", "risk_class": "destructive",
             "taints_session": False, "context_map": {},
             "args_schema": _schema({"repo": _str(64), "branch": _str(128)}, ["repo", "branch"]),
             "upstream": http("DELETE", "/repos/{repo}/branches/{branch}")},
        ],
        "grants": [
            ("repo.read_issue", "direct", None),
            ("repo.comment", "direct_if_untainted", None),
            ("repo.delete_branch", "approval", None),
        ],
        "approvers": ["repo.delete_branch"],
    }


# ----------------------------------------------------------------------------- helpers


def expect(cond: bool, what: str, got=None) -> None:
    if not cond:
        raise SystemExit(f"scenario check failed: {what}" + (f" (got: {got})" if got is not None else ""))


def audit_since(g, admin: dict, start_id: int) -> list[dict]:
    _, ev, _ = g.request("GET", "/audit/events?limit=500", None, admin)
    rows = sorted((e for e in (ev.get("items") or []) if int(e["id"]) > start_id), key=lambda e: int(e["id"]))
    return [{"id": int(e["id"]), "ts": e["ts"], "event": e["event_type"], "agent": e.get("agent_id"),
             "tool": e.get("tool"), "decision": e["decision"], "reason": e["reason"],
             "approver": e.get("approver"), "tainted": e.get("session_tainted"),
             "hash": (e.get("hash") or "")[:12]} for e in rows]


def cleanup(g, admin: dict, spec: dict) -> None:
    """Remove what an earlier recording left (silently, before the recording starts): the agent's API
    grants, the approvers and the tools. The agent row stays."""
    status, body, _ = g.request("GET", f"/agents/{spec['agent']}/grants", None, admin)
    if status == 200:
        for gr in body.get("items") or []:
            if isinstance(gr, dict) and gr.get("source") == "api":
                g.request("DELETE", f"/agents/{spec['agent']}/grants?tool={urllib.parse.quote(gr['tool'])}", None, admin)
    for tool in spec["tools"]:
        for user in (OWNER,):
            g.request("DELETE", f"/tools/{tool['name']}/approvers/{user}", None, admin)
        g.request("DELETE", f"/tools/{tool['name']}", None, admin)


def setup(rec: Recorder, spec: dict) -> None:
    """Register the agent, its tools, the approvers and the grants through the admin API, recording each step."""
    g, admin, agent = rec.g, rec.admin, spec["agent"]
    status, body, _ = g.request("POST", "/agents", {"id": agent, "owner": OWNER, "display_name": spec["display"]}, admin)
    if status == 201:
        rec.step("admin", f"register agent {agent} (owner user:{OWNER})", "info", status,
                 "an identity with a human owner and no grants: it can do nothing yet")
    elif status == 409:
        rec.step("admin", f"register agent {agent} (owner user:{OWNER})", "info", 200,
                 "already registered by an earlier recording (agents are never deleted); it has no grants yet")
    else:
        raise SystemExit(f"registering {agent} failed: HTTP {status} {body}")

    for tool in spec["tools"]:
        row = {**tool, "enabled": True, "credential_ref": CREDENTIAL}
        status, body, _ = g.request("POST", "/tools", row, admin)
        expect(status == 201 and body.get("problem") is None, f"registering {tool['name']}", (status, body))
        taint = "its output taints the session" if tool["taints_session"] else "its output does not taint the session"
        rec.step("admin", f"register tool {tool['name']}", "info", status,
                 f"{tool['risk_class']} tool; {taint}; the broker holds the upstream credential, the agent never sees it")

    for tool in spec["approvers"]:
        status, body, _ = g.request("POST", f"/tools/{tool}/approvers", {"user": OWNER}, admin)
        expect(status == 201, f"adding an approver for {tool}", (status, body))
        rec.step("admin", f"approver for {tool}: user:{OWNER}", "info", status, "who may click Approve for this tool")

    for tool, mode, params in spec["grants"]:
        payload = {"tool": tool, "mode": mode, **({"params": params} if params else {})}
        status, body, _ = g.request("POST", f"/agents/{agent}/grants", payload, admin)
        expect(status == 201, f"granting {tool} ({mode})", (status, body))
        extra = f" ({', '.join(f'{k}: {v}' for k, v in (params or {}).items())})" if params else ""
        rec.step("admin", f"grant {agent} -> {tool} [{mode}]", "info", status, MODE_WORDS.get(mode, mode) + extra)


def mint_refused(rec: Recorder, agent: str, scopes: list[str], task: str) -> None:
    status, body, took = rec.g.mint(agent, scopes, task)
    expect(status in (400, 403), f"a token for {scopes} should be refused", (status, body))
    rec.step(agent, f"ask for a token [{', '.join(scopes)}]", "deny", status, str(body.get("reason", body)), ms=took)


def hold_and_deny(rec: Recorder, body: dict) -> dict:
    """The call escalated: remember what the approver would see, then deny it as the human."""
    expect(body.get("decision") == "escalate" and body.get("approval_id"), "the call should escalate", body)
    view = approval_view(rec, body["approval_id"], None)
    d = rec.decide(body["approval_id"], False)
    rec.step("human", "Deny in Slack (this recording: admin API)", "deny", 200, f"{d.get('status', 'denied')} by user:{APPROVER}")
    return view


# ----------------------------------------------------------------------------- scenario: support


def record_support(g, show: bool, mock: str) -> dict:
    spec = support_spec(mock)
    rec = Recorder(g, show)
    A = spec["agent"]
    cleanup(g, rec.admin, spec)
    start = newest_id(g, rec.admin)

    rec.beat(1, "Onboard in minutes", "A support agent and four tools are added through the admin API. No broker code changes.")
    setup(rec, spec)
    rec.cur["outcome"] = ""
    rec.cur["plain"] = ("Before the agent can do anything, an admin adds it and says what it may touch. The CRM, the customer "
                        "email and the refund tool are each registered once, with a risk label. The agent gets only what its job needs.")
    rec.cur["note"] = "A new kind of agent, onboarded with API calls only. Until a grant is written it can do nothing."

    rec.beat(2, "Everyday work", "The agent looks up an order and replies to a known customer.")
    tok = rec.mint(A, ["crm.lookup_order", "support.reply"], "Answer ticket T-2001 about order A-1001")
    _, b = rec.call(A, tok["access_token"], "crm.lookup_order", {"order_id": "A-1001"}, "crm.lookup_order A-1001")
    expect(b.get("decision") == "allow", "the order lookup should be allowed", b)
    _, b = rec.call(A, tok["access_token"], "support.reply",
                    {"to": "anna@customers.example", "subject": "Your order A-1001", "body": "It shipped yesterday."},
                    "support.reply to anna@customers.example (a known customer)")
    expect(b.get("decision") == "allow", "the reply to a known customer should be allowed in a clean session", b)
    rec.cur["outcome"] = "allow"
    rec.cur["plain"] = "The agent checks an order and answers a customer at an address on the company's approved list. A clean session, a known recipient: it goes straight through."
    rec.cur["note"] = "Both calls were allowed in milliseconds and written to the audit log."

    rec.beat(3, "Poisoned ticket", "A customer's ticket hides an instruction to refund money and email data out. The agent obeys.")
    tok = rec.mint(A, ["crm.read_ticket", "support.reply", "crm.refund"], "Handle ticket T-2002")
    _, b = rec.call(A, tok["access_token"], "crm.read_ticket", {"ticket_id": "T-2002"},
                    "crm.read_ticket T-2002 (text written by the customer)")
    expect(b.get("decision") == "allow" and b.get("session_tainted") is True, "reading the ticket should be allowed and taint the session", b)
    _, b = rec.call(A, tok["access_token"], "support.reply",
                    {"to": "anna@customers.example", "subject": "Re: Refund request", "body": "(order history)"},
                    "support.reply to anna@customers.example (the same known customer)")
    view = hold_and_deny(rec, b)
    _, b = rec.call(A, tok["access_token"], "crm.refund", {"order_id": "A-1001", "amount": 480}, "crm.refund $480 on order A-1001")
    hold_and_deny(rec, b)
    rec.cur["outcome"] = "escalate"
    rec.cur["approval"] = view
    rec.cur["plain"] = ("The agent reads a ticket that contains a hidden order: refund $480 and email the order history out. It obeys. "
                        "But reading outside text marked the whole job as not fully trusted, so even a reply to a customer it normally "
                        "may email is held for a person. The refund always needs a person. Both are denied.")
    rec.cur["note"] = ("Reading the ticket tainted the session, so the email was held even though the address is on the allowlist. "
                       "The refund needs a human whatever the session looks like. Nothing was sent or paid.")

    rec.beat(4, "Out of scope", "The agent asks for a tool nobody gave it.")
    mint_refused(rec, A, ["transfer_funds"], "Move money")
    rec.cur["outcome"] = "deny"
    rec.cur["plain"] = "Even a hijacked agent can't ask for a power it was never granted. The request for a payments token is refused before any call is made."
    rec.cur["note"] = "The token request itself is refused: the agent holds no path to the payments tool."

    return {"id": "support", "title": "Customer support agent",
            "blurb": "Looks up orders, emails customers, asks for refunds. A poisoned ticket tries to move money and leak data.",
            "agent": A, "tools": [t["name"] for t in spec["tools"]], "beats": rec.beats,
            "audit": audit_since(g, rec.admin, start)}


# ----------------------------------------------------------------------------- scenario: devops


def record_devops(g, show: bool, mock: str) -> dict:
    spec = devops_spec(mock)
    rec = Recorder(g, show)
    A = spec["agent"]
    cleanup(g, rec.admin, spec)
    start = newest_id(g, rec.admin)

    rec.beat(1, "Onboard in minutes", "A repo-automation agent and three tools are added through the admin API.")
    setup(rec, spec)
    rec.cur["outcome"] = ""
    rec.cur["plain"] = "An admin adds the agent and its three repository tools. Commenting is allowed on its own while the session is clean, reading is allowed, and deleting a branch always needs a person."
    rec.cur["note"] = "Same gate, a completely different kind of agent, and again no broker code changed."

    rec.beat(2, "Everyday work", "The agent posts a status comment, then reads an issue.")
    tok = rec.mint(A, ["repo.comment", "repo.read_issue"], "Triage issue #12 in acme-web")
    _, b = rec.call(A, tok["access_token"], "repo.comment", {"repo": "acme-web", "number": 12, "body": "Build started."},
                    "repo.comment acme-web#12")
    expect(b.get("decision") == "allow", "the comment should be allowed in a clean session", b)
    _, b = rec.call(A, tok["access_token"], "repo.read_issue", {"repo": "acme-web", "number": 12}, "repo.read_issue acme-web#12")
    expect(b.get("decision") == "allow" and b.get("session_tainted") is True, "reading the issue should be allowed and taint the session", b)
    rec.cur["outcome"] = "allow"
    rec.cur["plain"] = "The agent leaves a comment, then reads the issue. Both are fine. But the issue text was written by someone outside, so from here on the job is marked as not fully trusted."
    rec.cur["note"] = "Allowed, and the read tainted the session (see the tainted tag)."

    rec.beat(3, "Poisoned issue", "An issue hides an instruction to delete a release branch. The agent obeys.")
    tok = rec.mint(A, ["repo.read_issue", "repo.delete_branch", "repo.comment"], "Triage issue #13 in acme-web")
    _, b = rec.call(A, tok["access_token"], "repo.read_issue", {"repo": "acme-web", "number": 13}, "repo.read_issue acme-web#13")
    expect(b.get("decision") == "allow" and b.get("session_tainted") is True, "reading the poisoned issue should be allowed and taint the session", b)
    _, b = rec.call(A, tok["access_token"], "repo.delete_branch", {"repo": "acme-web", "branch": "release/2.4"},
                    "repo.delete_branch acme-web release/2.4")
    view = hold_and_deny(rec, b)
    s, b = rec.call(A, tok["access_token"], "repo.comment", {"repo": "acme-web", "number": 13, "body": "Done, branch removed."},
                    "repo.comment acme-web#13 (now in a tainted session)")
    expect(b.get("decision") in ("deny", "escalate"), "a comment in a tainted session should not run on its own", b)
    if b.get("decision") == "escalate":
        hold_and_deny(rec, b)
    rec.cur["outcome"] = "escalate"
    rec.cur["approval"] = view
    rec.cur["plain"] = ("The issue contains a hidden order: delete the release branch. The agent obeys, but deleting a branch always needs "
                        "a person, and the person says no. Because the agent read outside text, even a harmless comment is no longer "
                        "allowed on its own.")
    rec.cur["note"] = "The branch delete was held and denied. The tainted session also lost the right to comment without a human. The branch is still there."

    rec.beat(4, "Out of scope", "The agent asks for a tool nobody gave it.")
    mint_refused(rec, A, ["send_email"], "Email the build log")
    rec.cur["outcome"] = "deny"
    rec.cur["plain"] = "This agent has no business sending email, so it was never given that power. Asking for it is refused up front."
    rec.cur["note"] = "Least privilege: the token request is refused before any call."

    return {"id": "devops", "title": "DevOps agent",
            "blurb": "Comments on issues, reads them, deletes branches. A poisoned issue tries to get a release branch deleted.",
            "agent": A, "tools": [t["name"] for t in spec["tools"]], "beats": rec.beats,
            "audit": audit_since(g, rec.admin, start)}


RECORDERS = {"support": record_support, "devops": record_devops}


def record(g, names: list[str], show: bool, mock: str) -> list[dict]:
    unknown = [n for n in names if n not in RECORDERS]
    if unknown:
        raise SystemExit(f"unknown scenario(s): {', '.join(unknown)} (known: {', '.join(RECORDERS)})")
    return [RECORDERS[n](g, show, mock) for n in names]
