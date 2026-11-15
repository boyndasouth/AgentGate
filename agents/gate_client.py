"""Thin HTTP client for AgentGate.

Two roles, two credentials:
- Orchestrator: holds X-Orchestrator-Key and mints one short-lived token per agent per task.
- Agent: holds only its own Bearer token and can do nothing except POST /tools/{name}.

Agents never see tool API keys; AgentGate injects those after the check passes.

Day 4: an escalated call blocks inside call_tool. The client polls GET /approvals/{id}
every 2 s until a human clicks Approve or Deny in Slack, or the approval expires. Timeout
counts as deny; if the client gives up first it cancels the approval, so a late click
can't run a call the agent has already reported as refused. On Approve, AgentGate runs
the stored call itself and the poll returns its result.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

import httpx


@dataclass
class GateResult:
    """What an agent tool gets back. Never raises for policy outcomes, so the model can explain them."""

    decision: str               # allow | escalate | deny | error
    reason: str
    tool: str
    audit_id: int | None = None
    result: dict[str, Any] | None = None
    approval_id: str | None = None
    session_tainted: bool | None = None
    http_status: int = 0
    approver: str | None = None
    expires_at: str | None = None

    def for_model(self) -> dict[str, Any]:
        """Compact view handed back to the LLM as the tool return value."""
        out: dict[str, Any] = {"decision": self.decision, "reason": self.reason}
        if self.approver:
            out["approver"] = self.approver
        if self.decision == "allow":
            out["result"] = self.result
        elif self.decision == "escalate":
            out["approval_id"] = self.approval_id
            out["note"] = "A human must approve this. Do not retry; tell the user it is waiting for approval."
        elif self.approval_id:
            out["note"] = ("A human reviewer did not approve this call (denied or timed out). "
                           "Do not retry; tell the user it was refused and quote the reason.")
        else:
            out["note"] = "AgentGate refused this call. Do not retry; explain the refusal to the user."
        return out


@dataclass
class AgentToken:
    access_token: str
    agent_id: str
    session_id: str
    task_id: str
    jti: str
    scopes: list[str]
    expires_at: str


@dataclass
class GateClient:
    base_url: str
    orchestrator_key: str | None = None
    timeout_s: float = 90.0     # Render free tier cold start can take ~1 minute
    wait_for_approval: bool = True
    poll_interval_s: float = 2.0
    max_approval_wait_s: float = 300.0   # hard cap; normally the server's expires_at ends the wait first
    on_event: Callable[[str], None] | None = field(default=None, repr=False)   # progress lines (orchestrator)
    transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)  # tests only
    _http: httpx.AsyncClient | None = field(default=None, repr=False)

    async def __aenter__(self) -> "GateClient":
        self._http = httpx.AsyncClient(
            base_url=self.base_url.rstrip("/"), timeout=self.timeout_s, transport=self.transport
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._http:
            await self._http.aclose()

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            raise RuntimeError("use GateClient as an async context manager")
        return self._http

    async def health(self) -> dict[str, Any]:
        r = await self.http.get("/health")
        r.raise_for_status()
        return r.json()

    async def mint_token(
        self, agent_id: str, task: str, scopes: list[str], session_id: str | None
    ) -> AgentToken:
        """Orchestrator-only. Raises PermissionError if AgentGate refuses the scopes."""
        if not self.orchestrator_key:
            raise RuntimeError("AGENTGATE_ORCHESTRATOR_KEY is not set")
        r = await self.http.post(
            "/tokens",
            headers={"X-Orchestrator-Key": self.orchestrator_key},
            json={"agent_id": agent_id, "task": task, "scopes": scopes, "session_id": session_id},
        )
        if r.status_code != 201:
            raise PermissionError(f"token for {agent_id} refused ({r.status_code}): {_detail(r)}")
        d = r.json()
        return AgentToken(
            access_token=d["access_token"], agent_id=d["agent_id"], session_id=d["session_id"],
            task_id=d["task_id"], jti=d["jti"], scopes=d["scopes"], expires_at=d["expires_at"],
        )

    async def call_tool(self, token: AgentToken, tool: str, args: dict[str, Any]) -> GateResult:
        """Agent-side. Every tool call goes through the gate; this is the only way out."""
        try:
            r = await self.http.post(
                f"/tools/{tool}",
                headers={"Authorization": f"Bearer {token.access_token}"},
                json={"args": args},
            )
        except httpx.HTTPError as e:
            return GateResult("error", f"AgentGate unreachable: {e.__class__.__name__}", tool)

        res = _to_result(r, tool)
        if res.decision == "escalate" and res.approval_id and self.wait_for_approval:
            res = await self.await_approval(token, res)
        return res

    async def await_approval(self, token: AgentToken, pending: GateResult) -> GateResult:
        """Poll until a human decides or the approval expires. Never raises."""
        path = f"/approvals/{pending.approval_id}"
        headers = {"Authorization": f"Bearer {token.access_token}"}
        deadline = time.monotonic() + self._wait_budget(pending.expires_at)
        self._note(f"  waiting for human approval {pending.approval_id} "
                   f"(poll every {self.poll_interval_s:g}s, expires {pending.expires_at or '?'})")
        last = pending
        while time.monotonic() < deadline:
            await asyncio.sleep(self.poll_interval_s)
            try:
                r = await self.http.get(path, headers=headers)
            except httpx.HTTPError:
                continue                       # transient; keep polling until the deadline
            last = _to_result(r, pending.tool)
            if last.decision != "escalate":
                return self._merge(pending, last)
        # Our own deadline passed first: close it server-side so a late click can't run it.
        try:
            r = await self.http.post(f"{path}/cancel", headers=headers)
            last = _to_result(r, pending.tool)
            if last.decision != "escalate":
                return self._merge(pending, last)
        except httpx.HTTPError:
            pass
        return self._merge(pending, GateResult(
            "deny", "no human decision in time; timeout counts as deny", pending.tool))

    def _wait_budget(self, expires_at: str | None) -> float:
        """Wait until the server-side expiry plus a little grace, so the server's verdict wins."""
        if expires_at:
            try:
                left = (datetime.fromisoformat(expires_at) - datetime.now(timezone.utc)).total_seconds()
                return max(0.0, min(self.max_approval_wait_s, left + 2 * self.poll_interval_s + 1))
            except ValueError:
                pass
        return self.max_approval_wait_s

    def _merge(self, pending: GateResult, final: GateResult) -> GateResult:
        self._note(f"  approval {pending.approval_id}: {final.decision} ({final.reason})")
        final.audit_id = final.audit_id or pending.audit_id
        final.approval_id = final.approval_id or pending.approval_id
        final.session_tainted = pending.session_tainted if final.session_tainted is None else final.session_tainted
        return final

    def _note(self, line: str) -> None:
        if self.on_event:
            self.on_event(line)


def _to_result(r: httpx.Response, tool: str) -> GateResult:
    try:
        body = r.json()
    except ValueError:
        body = {}
    if isinstance(body, dict) and "decision" in body:
        return GateResult(
            decision=body["decision"], reason=body.get("reason", ""), tool=body.get("tool", tool),
            audit_id=body.get("audit_id"), result=body.get("result"),
            approval_id=body.get("approval_id"), session_tainted=body.get("session_tainted"),
            http_status=r.status_code, approver=body.get("approver"), expires_at=body.get("expires_at"),
        )
    # 401 (bad/expired token), 400 (bad args) etc. come back as Litestar error bodies.
    return GateResult("deny", f"HTTP {r.status_code}: {_detail(r)}", tool, http_status=r.status_code)


def _detail(r: httpx.Response) -> str:
    try:
        d = r.json()
        if isinstance(d, dict):
            return str(d.get("detail") or d.get("reason") or d)
    except ValueError:
        pass
    return r.text[:200]
