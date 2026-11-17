"""Tiny stand-in for the AgentGate broker, for UI smoke tests only.

Implements the endpoints the UI calls with the real status codes
(200 allow / 202 escalate / 403 deny) and a simplified policy. Not the real
decision engine: it exists so the UI's server code can be exercised offline.
"""
import json, sys, uuid, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ADMIN, ORCH = "admin-key", "orch-key"
agents = {a: {"id": a, "owner": "user:shiwin", "display_name": a.title(), "status": "active"} for a in ("researcher", "mailer", "finance")}
tokens, sessions, approvals, events = {}, {}, {}, []
invoices = {}          # Day 10: id -> {"payee", "amount", "status"}
GRANTS = {             # Day 10: what GET /agents reads from OpenFGA in the real broker
    "researcher": [{"tool": "read_web", "mode": "direct", "condition": "untainted_or_allowed_host",
                    "context": {"allowed_hosts": ["example.com"]}, "taints": True, "approvers": []}],
    "mailer": [{"tool": "send_email", "mode": "direct", "condition": "untainted_allowed_recipient",
                "context": {"allowed_recipient_domains": ["agentgate.example"]}, "taints": False, "approvers": ["user:shiwin"]},
               {"tool": "send_email", "mode": "approval", "condition": None, "context": {}, "taints": False, "approvers": ["user:shiwin"]}],
    "finance": [{"tool": "transfer_funds", "mode": "direct", "condition": "within_limit_open_invoice",
                 "context": {"max_amount": 100, "allowed_payees": ["acct_acme_supplies"]}, "taints": False, "approvers": ["user:shiwin"]},
                {"tool": "transfer_funds", "mode": "approval", "condition": None, "context": {}, "taints": False, "approvers": ["user:shiwin"]}],
}
revoked_agents = {}
# Day 12: the registry and API-made grants, with the X-Admin-Via label the UI server sent
tools = {n: {"name": n, "risk_class": r, "taints_session": n.startswith("read"), "enabled": True, "problem": None,
             "upstream": {"kind": "builtin"}, "credential_ref": None, "context_map": {}, "approvers": []}
         for n, r in (("read_web", "read"), ("send_email", "egress"), ("transfer_funds", "money"))}
last_via = []
RISKY = ("egress", "money", "destructive")

def audit(**kw):
    events.append({"id": len(events) + 1, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ"), "decision": "info", "reason": "", **kw})
    return len(events)

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, body):
        b = json.dumps(body).encode()
        self.send_response(code); self.send_header("content-type", "application/json"); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def body(self):
        n = int(self.headers.get("content-length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")
    def admin(self): return self.headers.get("X-Admin-Key") == ADMIN
    def bearer(self):
        t = (self.headers.get("Authorization") or "").removeprefix("Bearer ")
        return tokens.get(t)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/__stop":
            import threading; threading.Thread(target=self.server.shutdown).start(); return self.send(200, {})
        if p == "/health": return self.send(200, {"status": "ok"})
        if p == "/audit/verify": return self.send(200, {"valid": True, "checked": len(events)})
        if p.startswith("/approvals/") and p.count("/") == 2:
            tok = self.bearer()
            if not tok: return self.send(401, {"detail": "bad token"})
            a = approvals.get(p.split("/")[2])
            if not a: return self.send(404, {"detail": "no such approval"})
            if a["status"] == "denied": return self.send(403, {"status": "denied", "reason": f"denied by {a['approver']}"})
            return self.send(200, {"status": a["status"]})
        if not self.admin(): return self.send(401, {"detail": "admin key required"})
        if p == "/agents": return self.send(200, [{**a, "auth0_client_id": a.get("auth0_client_id"), "login": "auth0" if a.get("auth0_client_id") else "orchestrator",
                                                  "grants": GRANTS.get(a["id"], []), "delegations": []} for a in agents.values()])
        if p == "/tools": return self.send(200, list(tools.values()))
        if p == "/approvals": return self.send(200, [{k: v for k, v in a.items() if k != "args"} for a in approvals.values() if a["status"] == "pending"])
        if p == "/audit/events": return self.send(200, list(reversed(events))[:50])
        self.send(404, {"detail": "not found"})

    def admin_write(self, method, p, b):
        """Day 12 admin API: strict like the real one (unknown fields -> 400)."""
        if not self.admin(): return self.send(401, {"detail": "admin key required"})
        via = self.headers.get("X-Admin-Via")
        if via is not None and not via.startswith("admin-ui:"): return self.send(400, {"reason": "bad via"})
        last_via.append(via or "admin-api")
        path, _, q = p.partition("?")
        parts = path.strip("/").split("/")
        if method == "POST" and path == "/agents":
            if set(b) - {"id", "owner", "display_name", "auth0_client_id"}: return self.send(400, {"reason": "Validation failed"})
            if b["id"] in agents: return self.send(409, {"reason": f"agent '{b['id']}' is already registered"})
            if b.get("auth0_client_id") and any(a.get("auth0_client_id") == b["auth0_client_id"] for a in agents.values()):
                return self.send(409, {"reason": "that Auth0 client is already mapped to another agent"})
            agents[b["id"]] = {"id": b["id"], "owner": b["owner"], "display_name": b.get("display_name", b["id"]), "status": "active",
                               "auth0_client_id": b.get("auth0_client_id")}
            return self.send(201, {**agents[b["id"]], "grants": []})
        if method == "PATCH" and len(parts) == 2 and parts[0] == "agents":      # Day 13: the agent's login
            if set(b) - {"display_name", "status", "reason", "auth0_client_id"}: return self.send(400, {"reason": "Validation failed"})
            a = agents.get(parts[1])
            if not a: return self.send(404, {"reason": "unknown agent"})
            if "auth0_client_id" in b:
                c = b["auth0_client_id"]
                if c and any(o.get("auth0_client_id") == c and o is not a for o in agents.values()):
                    return self.send(409, {"reason": "that Auth0 client is already mapped to another agent"})
                a["auth0_client_id"] = c
                revoked_agents[parts[1]] = time.time()
            return self.send(200, {**a, "login": "auth0" if a.get("auth0_client_id") else "orchestrator"})
        if method == "POST" and len(parts) == 3 and parts[0] == "agents" and parts[2] == "grants":
            if set(b) - {"tool", "mode", "params"}: return self.send(400, {"reason": "Validation failed"})
            t = tools.get(b["tool"])
            if not t: return self.send(404, {"reason": "unknown tool"})
            mode = b.get("mode") or ("approval" if t["risk_class"] in RISKY else "direct")
            warn = f"'{t['name']}' is a {t['risk_class']} tool" if mode == "direct" and t["risk_class"] in RISKY else None
            GRANTS.setdefault(parts[1], []).append({"tool": t["name"], "mode": "approval" if mode == "approval" else "direct",
                                                    "grant_mode": mode, "condition": None, "context": {}, "source": "api",
                                                    "risk_class": t["risk_class"], "approvers": []})
            return self.send(201, {"agent_id": parts[1], "tool": t["name"], "mode": mode, "params": b.get("params") or {},
                                   "defaulted": "mode" not in b, "warning": warn})
        if method == "DELETE" and len(parts) == 3 and parts[2] == "grants":
            qs = dict(x.split("=", 1) for x in q.split("&") if "=" in x)
            before = GRANTS.get(parts[1], [])
            keep = [g for g in before if not (g["tool"] == qs.get("tool") and g.get("source") == "api"
                                                and qs.get("mode") in (None, g.get("grant_mode")))]
            if len(keep) == len(before): return self.send(404, {"reason": "no such grant"})
            GRANTS[parts[1]] = keep
            return self.send(200, {"removed": [{"tool": qs.get("tool")}]})
        if method == "POST" and path == "/tools":
            if b.get("name") in tools: return self.send(409, {"reason": "tool exists"})
            tools[b["name"]] = {"enabled": False, "problem": None, "approvers": [], "taints_session": True, **b}
            return self.send(201, tools[b["name"]])
        if method == "PATCH" and len(parts) == 2 and parts[0] == "tools":
            if parts[1] not in tools: return self.send(404, {"reason": "unknown tool"})
            tools[parts[1]].update(b); return self.send(200, tools[parts[1]])
        if method == "POST" and len(parts) == 3 and parts[2] == "approvers":
            tools[parts[1]]["approvers"].append({"user": b["user"], "source": "api"})
            return self.send(201, {"tool": parts[1], "user": b["user"]})
        if method == "DELETE" and len(parts) == 4 and parts[2] == "approvers":
            tools[parts[1]]["approvers"] = [a for a in tools[parts[1]]["approvers"] if a["user"] != parts[3].replace("%3A", ":")]
            return self.send(200, {"tool": parts[1]})
        return None

    def do_PATCH(self):
        if self.admin_write("PATCH", self.path, self.body()) is None: self.send(404, {"detail": "not found"})

    def do_DELETE(self):
        if self.path == "/__via": return self.send(200, last_via)
        if self.admin_write("DELETE", self.path, {}) is None: self.send(404, {"detail": "not found"})

    def do_POST(self):
        p, b = self.path, self.body()
        if p in ("/agents", "/tools") or p.endswith("/grants") or p.endswith("/approvers"):
            if self.admin_write("POST", p, b) is None: self.send(404, {"detail": "not found"})
            return
        if p == "/tokens":
            if self.headers.get("X-Orchestrator-Key") != ORCH: return self.send(401, {"detail": "orchestrator key required"})
            ag = b["agent_id"]
            if agents[ag]["status"] == "disabled":
                audit(event_type="token_denied", agent_id=ag, decision="deny", reason="agent disabled"); return self.send(403, {"detail": "agent disabled"})
            sid = b.get("session_id") or str(uuid.uuid4()); sessions.setdefault(sid, {"tainted": False})
            t = "tok-" + uuid.uuid4().hex; jti = str(uuid.uuid4())
            tokens[t] = {"agent": ag, "sid": sid, "iat": time.time(), "scopes": b["scopes"]}
            audit(event_type="token_issued", agent_id=ag, session_id=sid, decision="allow", reason="ok", session_tainted=sessions[sid]["tainted"])
            return self.send(201, {"access_token": t, "token_type": "Bearer", "expires_in": 600, "expires_at": "", "agent_id": ag, "session_id": sid, "task_id": str(uuid.uuid4()), "jti": jti, "scopes": b["scopes"], "session_tainted": sessions[sid]["tainted"]})
        if p.startswith("/tools/"):
            tool, tok = p.split("/")[2], self.bearer()
            if not tok: return self.send(401, {"detail": "bad token"})
            ag, s = tok["agent"], sessions[tok["sid"]]
            if revoked_agents.get(ag, 0) >= tok["iat"]:
                i = audit(event_type="tool_call", agent_id=ag, tool=tool, decision="deny", reason="token revoked (kill switch)", session_tainted=s["tainted"])
                return self.send(403, {"decision": "deny", "reason": "token revoked (kill switch)", "tool": tool, "audit_id": i})
            args = b.get("args", {})
            inv = invoices.get(args.get("invoice_id", ""))
            inv_ok = bool(inv) and inv["status"] == "open" and inv["payee"] == args.get("to_account") and inv["amount"] == args.get("amount")
            esc = (tool == "transfer_funds" and (args.get("amount", 0) > 100 or s["tainted"] or args.get("to_account") != "acct_acme_supplies" or not inv_ok)) or (tool == "send_email" and (s["tainted"] or not str(args.get("to", "")).lower().endswith("@agentgate.example")))
            if esc:
                aid = str(uuid.uuid4()); reason = "session tainted by read_web" if s["tainted"] else ("recipient is not on the allowlist" if tool == "send_email" else "amount over limit")
                approvals[aid] = {"id": aid, "agent_id": ag, "tool": tool, "reason": reason, "status": "pending", "session_tainted": s["tainted"], "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 120)), "args": args}
                i = audit(event_type="tool_call", agent_id=ag, tool=tool, decision="escalate", reason=reason, session_tainted=s["tainted"])
                return self.send(202, {"decision": "escalate", "reason": reason, "tool": tool, "audit_id": i, "approval_id": aid, "status": "pending", "session_tainted": s["tainted"]})
            if tool == "transfer_funds": inv["status"] = "paid"
            pre = s["tainted"]
            i = audit(event_type="tool_call", agent_id=ag, tool=tool, decision="allow", reason="direct_invoker", session_tainted=pre)
            if tool in ("read_web", "read_inbox") and not s["tainted"]:
                s["tainted"] = True; audit(event_type="session_tainted", agent_id=ag, decision="info", reason=f"tainted by {tool}", session_tainted=True)
            return self.send(200, {"decision": "allow", "reason": "direct_invoker", "tool": tool, "audit_id": i, "session_tainted": s["tainted"], "result": {"ok": True, "customers": [{"name": "Ada"}]} if tool == "query_customers" else {"ok": True}})
        if not self.admin(): return self.send(401, {"detail": "admin key required"})
        if p == "/invoices":
            iid = b.get("id") or "INV-" + uuid.uuid4().hex[:8].upper()
            invoices[iid] = {"payee": b["payee"], "amount": b["amount"], "status": "open"}
            return self.send(201, {"id": iid, **invoices[iid]})
        if p.startswith("/delegations/") and p.endswith("/revoke"):
            return self.send(404, {"detail": "unknown delegation"})
        if p.endswith("/disable") or p.endswith("/enable"):
            ag = p.split("/")[2]; dis = p.endswith("/disable")
            agents[ag]["status"] = "disabled" if dis else "active"
            if dis: revoked_agents[ag] = time.time()
            audit(event_type="agent_disabled" if dis else "agent_enabled", agent_id=ag, reason=b.get("reason", "") if dis else "enabled")
            return self.send(200, {"agent_id": ag, "status": agents[ag]["status"]})
        if p.endswith("/decision"):
            a = approvals.get(p.split("/")[2])
            if not a or a["status"] != "pending": return self.send(409, {"detail": "already decided"})
            if not {"approve", "approver"} <= set(b) <= {"approve", "approver", "via"} or not str(b.get("via", "admin-ui:x")).startswith("admin-ui:"): return self.send(400, {"detail": "Validation failed for POST " + p})
            if b.get("approver") != "user:shiwin": return self.send(403, {"detail": f"{b.get('approver')} is not an approver"})
            a["status"] = "approved" if b["approve"] else "denied"; a["approver"] = f"{b['approver']} via {b.get('via', 'admin-api')}"
            audit(event_type="approval_resolved", agent_id=a["agent_id"], tool=a["tool"], decision="allow" if b["approve"] else "deny", reason=a["status"], approver=a["approver"])
            return self.send(200, {"id": a["id"], "status": a["status"]})
        self.send(404, {"detail": "not found"})

ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8765), H).serve_forever()
