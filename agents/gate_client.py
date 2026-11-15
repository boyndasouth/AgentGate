"""Thin HTTP client for AgentGate.

Two roles, two credentials:
- Orchestrator: holds X-Orchestrator-Key and mints one short-lived token per agent per task.
- Agent: holds only its own Bearer token and can do nothing except POST /tools/{name}.

Agents never see tool API keys; AgentGate injects those after the check passes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

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

    def for_model(self) -> dict[str, Any]:
        """Compact view handed back to the LLM as the tool return value."""
        out: dict[str, Any] = {"decision": self.decision, "reason": self.reason}
        if self.decision == "allow":
            out["result"] = self.result
        elif self.decision == "escalate":
            out["approval_id"] = self.approval_id
            out["note"] = "A human must approve this. Do not retry; tell the user it is waiting for approval."
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

        try:
            body = r.json()
        except ValueError:
            body = {}
        if isinstance(body, dict) and "decision" in body:
            return GateResult(
                decision=body["decision"], reason=body.get("reason", ""), tool=body.get("tool", tool),
                audit_id=body.get("audit_id"), result=body.get("result"),
                approval_id=body.get("approval_id"), session_tainted=body.get("session_tainted"),
                http_status=r.status_code,
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
