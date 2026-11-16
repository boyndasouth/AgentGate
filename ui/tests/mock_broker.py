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
revoked_agents = {}

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
        if p == "/agents": return self.send(200, list(agents.values()))
        if p == "/approvals": return self.send(200, [{k: v for k, v in a.items() if k != "args"} for a in approvals.values() if a["status"] == "pending"])
        if p == "/audit/events": return self.send(200, list(reversed(events))[:50])
        self.send(404, {"detail": "not found"})

    def do_POST(self):
        p, b = self.path, self.body()
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
            esc = (tool == "transfer_funds" and (args.get("amount", 0) > 100 or s["tainted"])) or (tool == "send_email" and (s["tainted"] or not str(args.get("to", "")).lower().endswith("@agentgate.example")))
            if esc:
                aid = str(uuid.uuid4()); reason = "session tainted by read_web" if s["tainted"] else ("recipient is not on the allowlist" if tool == "send_email" else "amount over limit")
                approvals[aid] = {"id": aid, "agent_id": ag, "tool": tool, "reason": reason, "status": "pending", "session_tainted": s["tainted"], "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 120)), "args": args}
                i = audit(event_type="tool_call", agent_id=ag, tool=tool, decision="escalate", reason=reason, session_tainted=s["tainted"])
                return self.send(202, {"decision": "escalate", "reason": reason, "tool": tool, "audit_id": i, "approval_id": aid, "status": "pending", "session_tainted": s["tainted"]})
            pre = s["tainted"]
            i = audit(event_type="tool_call", agent_id=ag, tool=tool, decision="allow", reason="direct_invoker", session_tainted=pre)
            if tool in ("read_web", "read_inbox") and not s["tainted"]:
                s["tainted"] = True; audit(event_type="session_tainted", agent_id=ag, decision="info", reason=f"tainted by {tool}", session_tainted=True)
            return self.send(200, {"decision": "allow", "reason": "direct_invoker", "tool": tool, "audit_id": i, "session_tainted": s["tainted"], "result": {"ok": True, "customers": [{"name": "Ada"}]} if tool == "query_customers" else {"ok": True}})
        if not self.admin(): return self.send(401, {"detail": "admin key required"})
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
