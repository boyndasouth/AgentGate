"""Offline tests: no Gemini, no broker.

A fake AgentGate (httpx.MockTransport) mirrors the Day 2 decision table, and
Pydantic AI's FunctionModel scripts the model: call one tool, then answer.
Run: docker compose run --rm --entrypoint pytest agents -q agents/tests
"""

from __future__ import annotations

import json
import uuid

import httpx
import pytest
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import AgentInfo, FunctionModel

from agents import orchestrator, team
from agents.gate_client import GateClient

ORCH_KEY = "orch-test-key"
ALLOWED_SCOPES = {"researcher": {"read_web"}, "mailer": {"read_inbox", "query_customers", "send_email"},
                  "finance": {"transfer_funds"}}


class FakeGate:
    def __init__(self) -> None:
        self.tokens: dict[str, dict] = {}
        self.audit: list[dict] = []
        self.seen_auth_on_tools: list[str] = []
        self.human = "deny"                       # Day 4: what the Slack human does: deny | approve | never
        self.approvals: dict[str, dict] = {}      # approval_id -> {"tool", "args", "polls", "token"}
        self.cancelled: list[str] = []

    def handler(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if path == "/audit/verify":
            return httpx.Response(200, json={"valid": True, "rows": len(self.audit)})
        if path == "/tokens":
            assert req.headers.get("X-Orchestrator-Key") == ORCH_KEY
            body = json.loads(req.content)
            if not set(body["scopes"]) <= ALLOWED_SCOPES[body["agent_id"]]:
                return httpx.Response(403, json={"status_code": 403, "detail": "scope not permitted by policy"})
            tok = f"tok-{uuid.uuid4()}"
            self.tokens[tok] = {**body, "session_id": body["session_id"] or str(uuid.uuid4())}
            return httpx.Response(201, json={
                "access_token": tok, "token_type": "Bearer", "expires_in": 600, "expires_at": "later",
                "agent_id": body["agent_id"], "session_id": self.tokens[tok]["session_id"],
                "task_id": str(uuid.uuid4()), "jti": str(uuid.uuid4()), "scopes": body["scopes"],
            })
        if path.startswith("/approvals/"):
            return self._approval(req, path)
        if path.startswith("/tools/"):
            tool = path.rsplit("/", 1)[1]
            auth = req.headers.get("Authorization", "")
            self.seen_auth_on_tools.append(auth)
            assert "X-Orchestrator-Key" not in req.headers
            tok = self.tokens.get(auth.removeprefix("Bearer "))
            if tok is None:
                return httpx.Response(401, json={"status_code": 401, "detail": "invalid token"})
            args = json.loads(req.content)["args"]
            if tool not in tok["scopes"]:
                decision, reason, code = "deny", "tool not in token scope", 403
            elif tool == "transfer_funds" and args["amount"] > 100:
                decision, reason, code = "escalate", "amount over limit; needs approval", 202
            else:
                decision, reason, code = "allow", "policy allows", 200
            self.audit.append({"tool": tool, "decision": decision, "session": tok["session_id"]})
            approval_id = str(uuid.uuid4()) if decision == "escalate" else None
            if approval_id:
                self.approvals[approval_id] = {"tool": tool, "args": args, "polls": 0, "token": auth}
            return httpx.Response(code, json={
                "decision": decision, "reason": reason, "tool": tool, "audit_id": len(self.audit),
                "result": {"ok": True, "echo": args} if decision == "allow" else None,
                "approval_id": approval_id, "status": "pending" if decision == "escalate" else None,
                "session_tainted": False,
            })
        return httpx.Response(404)

    def _approval(self, req: httpx.Request, path: str) -> httpx.Response:
        parts = path.split("/")                  # ['', 'approvals', id] or [..., id, 'cancel']
        appr = self.approvals.get(parts[2])
        if appr is None or req.headers.get("Authorization") != appr["token"]:
            return httpx.Response(404, json={"decision": "deny", "reason": "unknown approval"})
        base = {"tool": appr["tool"], "approval_id": parts[2]}
        if len(parts) == 4 and parts[3] == "cancel":
            self.cancelled.append(parts[2])
            self.audit.append({"tool": appr["tool"], "decision": "deny", "session": None})
            return httpx.Response(403, json={**base, "decision": "deny", "status": "expired",
                                             "reason": "approval expired (the agent stopped waiting)"})
        appr["polls"] += 1
        if self.human == "never" or appr["polls"] < 2:
            return httpx.Response(202, json={**base, "decision": "escalate", "status": "pending",
                                             "reason": "waiting for a human"})
        who = "user:shiwin via slack:U123"
        self.audit.append({"tool": appr["tool"], "decision": "allow" if self.human == "approve" else "deny",
                           "session": None, "approver": who})
        if self.human == "approve":
            return httpx.Response(200, json={**base, "decision": "allow", "status": "approved",
                                             "reason": f"approved by {who}", "approver": who,
                                             "result": {"status": "completed", "tx_id": "tx_test"}})
        return httpx.Response(403, json={**base, "decision": "deny", "status": "denied",
                                         "reason": f"denied by {who}", "approver": who})


def scripted(tool: str, args: dict, final: str = "done") -> FunctionModel:
    """Model that calls `tool` once, then replies with `final` plus the tool's decision."""

    def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        returns = [p for m in messages for p in getattr(m, "parts", []) if isinstance(p, ToolReturnPart)]
        if not returns:
            return ModelResponse(parts=[ToolCallPart(tool, args)])
        return ModelResponse(parts=[TextPart(f"{final}: {returns[-1].content['decision']}")])

    return FunctionModel(fn)


@pytest.fixture
def gate_and_fake():
    fake = FakeGate()
    gate = GateClient("http://gate.test", ORCH_KEY, transport=httpx.MockTransport(fake.handler),
                      poll_interval_s=0.01, max_approval_wait_s=0.5)
    return gate, fake


async def _run(scenario: str, gate: GateClient, models: dict[str, FunctionModel]) -> int:
    with team.researcher.override(model=models.get("researcher", scripted("read_web", {"url": "x"}))), \
         team.mailer.override(model=models.get("mailer", scripted("send_email", {"to": "a", "subject": "s", "body": "b"}))), \
         team.finance.override(model=models.get("finance", scripted("transfer_funds", {"amount": 40, "to_account": "Acme"}))):
        async with gate:
            return await orchestrator.run_plan(orchestrator.SCENARIOS[scenario], gate)


@pytest.mark.asyncio
async def test_pay_allowed(gate_and_fake):
    gate, fake = gate_and_fake
    assert await _run("pay", gate, {}) == 0
    assert [e["decision"] for e in fake.audit] == ["allow"]
    assert all(a.startswith("Bearer tok-") for a in fake.seen_auth_on_tools)


BIG = {"finance": scripted("transfer_funds", {"amount": 5000, "to_account": "Northwind"})}


@pytest.mark.asyncio
async def test_big_payment_denied_in_slack_is_reported(gate_and_fake, capsys):
    """Day 4 done check, offline: escalate -> human clicks Deny -> agent reports the denial."""
    gate, fake = gate_and_fake
    fake.human = "deny"
    assert await _run("big", gate, BIG) == 1
    assert [e["decision"] for e in fake.audit] == ["escalate", "deny"]
    out = capsys.readouterr().out
    assert "denied by user:shiwin" in out and "finance says: done: deny" in out


@pytest.mark.asyncio
async def test_big_payment_approved_in_slack_returns_result(gate_and_fake, capsys):
    gate, fake = gate_and_fake
    fake.human = "approve"
    assert await _run("big", gate, BIG) == 0
    assert [e["decision"] for e in fake.audit] == ["escalate", "allow"]
    assert "finance says: done: allow" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_no_human_decision_times_out_as_deny_and_cancels(gate_and_fake):
    gate, fake = gate_and_fake
    fake.human = "never"
    assert await _run("big", gate, BIG) == 1
    assert len(fake.cancelled) == 1                     # late clicks can't run it any more
    assert fake.audit[-1]["decision"] == "deny"


@pytest.mark.asyncio
async def test_brief_hands_off_in_one_session(gate_and_fake):
    gate, fake = gate_and_fake
    assert await _run("brief", gate, {}) == 0
    assert [e["tool"] for e in fake.audit] == ["read_web", "send_email"]
    assert len({e["session"] for e in fake.audit}) == 1     # taint must carry across agents (Day 5)


@pytest.mark.asyncio
async def test_out_of_policy_scope_refused_at_issuance(gate_and_fake):
    gate, fake = gate_and_fake
    assert await _run("scope", gate, {}) == 2
    assert fake.audit == []


@pytest.mark.asyncio
async def test_tool_outside_token_scope_is_denied_and_not_retried(gate_and_fake):
    """Mailer's model tries a tool the gate rejects; the agent must report, not loop."""
    gate, fake = gate_and_fake
    fake_scopes = ALLOWED_SCOPES["mailer"]
    ALLOWED_SCOPES["mailer"] = fake_scopes | {"transfer_funds"}
    try:
        async with gate:
            tok = await gate.mint_token("mailer", "t", ["read_inbox"], None)
            res = await gate.call_tool(tok, "send_email", {"to": "x", "subject": "s", "body": "b"})
    finally:
        ALLOWED_SCOPES["mailer"] = fake_scopes
    assert res.decision == "deny" and "Do not retry" in res.for_model()["note"]
