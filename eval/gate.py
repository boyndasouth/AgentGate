"""Tiny AgentGate HTTP client shared by the Day 7 evals. Stdlib only, so it runs
anywhere: Windows Python, or the python:3.12-slim container that scripts/run_eval.ps1 uses.

Config comes from an env file (never printed):
  --target local   -> .env         URL: $AGENTGATE_URL or http://localhost:8000
  --target render  -> .env.render  URL: AGENTGATE_URL from the file
"""

from __future__ import annotations

import http.client
import json
import os
import ssl
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        raise SystemExit(f"{path} not found (run from the repo root)")
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip().removeprefix("export ").strip()] = v.strip().strip('"').strip("'")
    return out


@dataclass
class Config:
    target: str
    base_url: str
    orchestrator_key: str
    admin_key: str


def load_config(target: str) -> Config:
    env = read_env_file(REPO / (".env.render" if target == "render" else ".env"))
    if target == "render":
        url = os.environ.get("AGENTGATE_URL") or env.get("AGENTGATE_URL", "")
    else:
        url = os.environ.get("AGENTGATE_URL", "http://localhost:8000")
    keys = {k: os.environ.get(k) or env.get(k, "") for k in ("AGENTGATE_ORCHESTRATOR_KEY", "AGENTGATE_ADMIN_KEY")}
    missing = [k for k, v in keys.items() if not v]
    if missing or not url:
        raise SystemExit(f"missing in env file: {', '.join(missing) or 'AGENTGATE_URL'}")
    return Config(target, url.rstrip("/"), keys["AGENTGATE_ORCHESTRATOR_KEY"], keys["AGENTGATE_ADMIN_KEY"])


class Gate:
    """Keep-alive HTTP client (one connection, reconnects on failure), so latency numbers
    measure the broker, not TCP/TLS setup."""

    def __init__(self, cfg: Config, timeout: float = 90.0) -> None:
        self.cfg = cfg
        u = urllib.parse.urlsplit(cfg.base_url)
        self._https = u.scheme == "https"
        self._host, self._port = u.hostname, u.port
        self._prefix = u.path.rstrip("/")
        self._timeout = timeout
        self._conn: http.client.HTTPConnection | None = None

    def _connect(self) -> http.client.HTTPConnection:
        if self._https:
            return http.client.HTTPSConnection(self._host, self._port, timeout=self._timeout,
                                               context=ssl.create_default_context())
        return http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)

    def request(self, method: str, path: str, body: dict | None = None,
                headers: dict[str, str] | None = None) -> tuple[int, dict, float]:
        """Returns (status, json body or {}, elapsed seconds). Never raises on an HTTP status."""
        data = json.dumps(body).encode() if body is not None else None
        hdrs = {"Accept": "application/json", **(headers or {})}
        if data is not None:
            hdrs["Content-Type"] = "application/json"
        for attempt in (1, 2):
            if self._conn is None:
                self._conn = self._connect()
            try:
                t0 = time.perf_counter()
                self._conn.request(method, self._prefix + path, body=data, headers=hdrs)
                resp = self._conn.getresponse()
                raw = resp.read()
                elapsed = time.perf_counter() - t0
                break
            except (http.client.HTTPException, OSError):
                self._conn.close()
                self._conn = None
                if attempt == 2:
                    raise
        try:
            parsed = json.loads(raw) if raw else {}
        except ValueError:
            parsed = {"reason": raw[:200].decode(errors="replace")}
        return resp.status, parsed if isinstance(parsed, dict) else {"items": parsed}, elapsed

    # -- helpers ---------------------------------------------------------------

    def wait_healthy(self, max_wait: float = 120.0) -> dict:
        """Render's free tier sleeps; the first request can take ~1 min."""
        deadline = time.monotonic() + max_wait
        last = "no answer"
        while True:
            try:
                status, body, _ = self.request("GET", "/health")
                if status == 200 and body.get("openfga"):
                    return body
                last = f"HTTP {status} {body}"
            except OSError as e:
                last = f"{type(e).__name__}: {e}"
            if time.monotonic() > deadline:
                raise SystemExit(f"broker not healthy at {self.cfg.base_url}/health "
                                 f"(is it running? is OpenFGA up?) last: {last}")
            time.sleep(3)

    def mint(self, agent: str, scopes: list[str], task: str, session_id: str | None = None):
        body = {"agent_id": agent, "task": task, "scopes": scopes}
        if session_id:
            body["session_id"] = session_id
        return self.request("POST", "/tokens", body, {"X-Orchestrator-Key": self.cfg.orchestrator_key})

    def tool(self, token: str, name: str, args: dict):
        return self.request("POST", f"/tools/{name}", {"args": args}, {"Authorization": f"Bearer {token}"})

    def cancel(self, token: str, approval_id: str):
        return self.request("POST", f"/approvals/{approval_id}/cancel", None,
                            {"Authorization": f"Bearer {token}"})

    def delegate(self, token: str, delegate: str, tools: list[str], ttl_seconds: int = 300, task: str = ""):
        """Day 10: the token's holder grants `delegate` some of its tools."""
        return self.request("POST", "/delegations", {"delegate": delegate, "tools": tools, "ttl_seconds": ttl_seconds,
                                                     "task": task}, {"Authorization": f"Bearer {token}"})

    def exchange(self, token: str, delegation_id: str, scopes: list[str], task: str = ""):
        """Day 10: trade the agent's own token for one acting through `delegation_id`."""
        return self.request("POST", "/tokens/exchange", {"delegation_id": delegation_id, "scopes": scopes,
                                                         "task": task}, {"Authorization": f"Bearer {token}"})

    def admin(self, method: str, path: str, body: dict | None = None):
        return self.request(method, path, body, {"X-Admin-Key": self.cfg.admin_key})
