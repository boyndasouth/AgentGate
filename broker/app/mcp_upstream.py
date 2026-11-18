"""Day 14: forwarding an allowed call to a remote MCP server (`upstream.kind = "mcp"`).

A registry row says which remote tool it stands for:

    {"kind": "mcp", "url": "https://mcp.example.com/mcp", "tool": "create_issue",
     "auth": {"type": "bearer"},                       # same forms as an http upstream
     "timeout_seconds": 15, "max_response_bytes": 262144}

and `credential_ref` names the env var holding the secret (UPSTREAM_*), exactly as for http tools.
The agent never talks to the remote server and never sees its credential; the gate decides first,
and only an allowed call reaches this module.

Everything the http upstream refuses, this refuses, because every request goes through the same
checks: https only (or a host in UPSTREAM_PRIVATE_HOSTS), no host from arguments, the address is
resolved once and must be public, the connection goes to that address, redirects are never
followed, responses are size-capped while they are read, and the credential is scrubbed from
what comes back. The URL is fixed in the row, never built from arguments.

Each call is one short MCP session: initialize, initialized, tools/call, then a best-effort
DELETE of the session. Nothing is kept between calls, so there is no remote session to leak.
Error texts are written here; a message the remote server sends is never copied to the agent.
The result's text comes from the remote server and is untrusted: the tool row says whether it
taints the session (an imported tool does by default).

Import (`discover`): asks the remote server for its tools/list; admin_api turns the answer into
registry rows that are DISABLED, risk class `destructive` and tainting, with no grants.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Mapping

import httpx

from . import upstream as up
from .upstream import HttpPlan, UpstreamError

REMOTE_TOOL = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
PROTOCOL_VERSION = "2025-11-25"       # a handshake-era version; the server may answer with an older one
_KEYS = {"kind", "url", "tool", "auth", "headers", "timeout_seconds", "max_response_bytes"}
MAX_IMPORT_TOOLS = 100


@dataclass(frozen=True)
class McpPlan:
    """A registry row's `upstream` for kind 'mcp', checked once at load time."""
    http: HttpPlan          # where and how to connect (URL, auth, timeout, size cap)
    remote_tool: str        # the tool name on the remote server


def compile_mcp(upstream: Mapping[str, Any], schema: Mapping[str, Any], credential_ref: Any,
                env: Mapping[str, str] | None = None) -> tuple[McpPlan | None, str | None]:
    """Check an mcp `upstream`. Returns (plan, None) or (None, why it can't be used). Never raises."""
    unknown = sorted(set(upstream) - _KEYS)
    if unknown:
        return None, f"upstream has an unknown key ({', '.join(str(k)[:40] for k in unknown[:3])})"
    tool = upstream.get("tool")
    if not isinstance(tool, str) or not REMOTE_TOOL.fullmatch(tool):
        return None, "upstream.tool must be the remote tool's name (letters, digits and _ . : -)"
    url = upstream.get("url")
    if isinstance(url, str) and ("{" in url or "}" in url):
        return None, "upstream.url for an mcp tool can't have {placeholders}"
    as_http = {k: v for k, v in upstream.items() if k in ("url", "auth", "headers", "timeout_seconds", "max_response_bytes")}
    plan, why = up.compile_http({**as_http, "method": "POST", "send_args": "json"}, {}, credential_ref, env)
    if why:
        return None, why
    return McpPlan(http=plan, remote_tool=tool), None


# ---------------------------------------------------------------- one request


def _parse(ctype: str, raw: bytes, want_id: int | None) -> dict | None:
    """The JSON-RPC message with `id == want_id` from a JSON or an event-stream body."""
    text = raw.decode("utf-8", errors="replace")
    messages: list[Any] = []
    if "event-stream" in ctype.lower():
        for block in re.split(r"\r?\n\r?\n", text):
            data = "\n".join(line[5:].lstrip(" ") for line in block.splitlines() if line.startswith("data:"))
            if data:
                try:
                    messages.append(json.loads(data))
                except ValueError:
                    continue
    else:
        try:
            messages.append(json.loads(text))
        except (ValueError, RecursionError):
            return None
    for m in messages:
        for item in (m if isinstance(m, list) else [m]):
            if isinstance(item, dict) and item.get("id") == want_id and ("result" in item or "error" in item):
                return item
    return None


async def _request(plan: HttpPlan, secret: str, *, method: str = "POST", payload: dict | None = None,
                   session_id: str | None = None, version: str | None = None,
                   want_id: int | None = None) -> tuple[int, dict[str, str], dict | None]:
    """One hardened request. Returns (status, headers, the answer message if `want_id` was given)."""
    headers = dict(plan.headers)
    headers["Accept"] = "application/json, text/event-stream"
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    if version:
        headers["MCP-Protocol-Version"] = version
    if secret:
        headers[plan.auth_header] = plan.auth_prefix + secret
    addr = await up._resolve(plan)
    literal = f"[{addr.split('%')[0]}]" if ":" in addr else addr
    url = f"{plan.scheme}://{literal}:{plan.port}{plan.path}" + (f"?{plan.query}" if plan.query else "")
    headers["Host"] = plan.host if plan.port == up._default_port(plan.scheme) else f"{plan.host}:{plan.port}"
    extensions = {"sni_hostname": plan.host} if plan.scheme == "https" else {}
    timeout = httpx.Timeout(plan.timeout, connect=min(plan.timeout, 5.0))
    content = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
    try:
        async with asyncio.timeout(plan.timeout):
            async with up._http().stream(method, url, headers=headers, content=content, timeout=timeout,
                                         extensions=extensions) as resp:
                if 300 <= resp.status_code < 400:
                    raise UpstreamError(f"the MCP server answered {resp.status_code} (a redirect); "
                                        "redirects are never followed")
                chunks, size = [], 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > plan.max_bytes:
                        raise UpstreamError(f"the MCP server's answer is larger than {plan.max_bytes} bytes")
                    chunks.append(chunk)
                status, ctype = resp.status_code, resp.headers.get("content-type", "")
                got = {k.lower(): v for k, v in resp.headers.items()}
    except UpstreamError:
        raise
    except (TimeoutError, httpx.TimeoutException):
        raise UpstreamError(f"the MCP server did not answer within {plan.timeout:g} s") from None
    except httpx.ConnectError:
        raise UpstreamError("could not connect to the MCP server (network or TLS error)") from None
    except httpx.HTTPError as exc:
        raise UpstreamError(f"the MCP request failed ({type(exc).__name__})") from None
    message = _parse(ctype, b"".join(chunks), want_id) if want_id is not None and 200 <= status < 300 else None
    return status, got, message


def _secret(plan: HttpPlan, credential_ref: str | None) -> str:
    if plan.auth == "none":
        return ""
    if up.credential_problem(credential_ref):
        raise UpstreamError("the upstream credential is not available in the broker's environment")
    return os.environ[credential_ref]


class _Session:
    """initialize -> initialized, then whatever `run` does, then a best-effort DELETE."""

    def __init__(self, plan: HttpPlan, secret: str) -> None:
        self.plan, self.secret = plan, secret
        self.sid: str | None = None
        self.version: str | None = None
        self._next = 1

    async def __aenter__(self) -> "_Session":
        status, headers, msg = await _request(
            self.plan, self.secret, want_id=0, payload={
                "jsonrpc": "2.0", "id": 0, "method": "initialize",
                "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                           "clientInfo": {"name": "agentgate-broker", "version": "0.11"}}})
        if status in (401, 403):
            raise UpstreamError(f"the MCP server refused the broker's credential ({status})")
        if msg is None or "result" not in msg:
            raise UpstreamError(f"the MCP server did not complete the handshake (HTTP {status})")
        self.sid = headers.get("mcp-session-id")
        version = msg["result"].get("protocolVersion") if isinstance(msg["result"], dict) else None
        self.version = version if isinstance(version, str) and len(version) <= 16 else PROTOCOL_VERSION
        await _request(self.plan, self.secret, session_id=self.sid, version=self.version,
                       payload={"jsonrpc": "2.0", "method": "notifications/initialized"})
        return self

    async def rpc(self, method: str, params: dict) -> Any:
        self._next += 1
        status, _, msg = await _request(
            self.plan, self.secret, session_id=self.sid, version=self.version, want_id=self._next,
            payload={"jsonrpc": "2.0", "id": self._next, "method": method, "params": params})
        if msg is None:
            raise UpstreamError(f"the MCP server gave no usable answer to {method} (HTTP {status})")
        if "error" in msg:
            code = msg["error"].get("code") if isinstance(msg["error"], dict) else None
            raise UpstreamError(f"the MCP server returned an error to {method}"
                                + (f" (code {code})" if isinstance(code, int) else ""))
        return msg["result"]

    async def __aexit__(self, *exc: object) -> None:
        if self.sid:
            try:
                async with asyncio.timeout(3):
                    await _request(self.plan, self.secret, method="DELETE", session_id=self.sid, version=self.version)
            except Exception:      # noqa: BLE001 - best effort; the remote session expires on its own
                pass


# ---------------------------------------------------------------- the two operations


def _text_of(result: dict) -> tuple[str, Any]:
    """Text from a tools/call result. Images and other media are named, never forwarded."""
    parts: list[str] = []
    for item in result.get("content") or []:
        if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
            parts.append(item["text"])
        elif isinstance(item, dict):
            parts.append(f"[{str(item.get('type', 'content'))[:20]} content omitted]")
    structured = result.get("structuredContent")
    return "\n".join(parts), structured if isinstance(structured, dict) else None


async def call(plan: McpPlan, credential_ref: str | None, args: Mapping[str, Any]) -> dict:
    """Call the remote tool and return {"ok", "body"} (and "structured" when the server sent
    some), scrubbed of the credential. Raises UpstreamError (safe text) when there is no usable answer."""
    secret = _secret(plan.http, credential_ref)
    async with _Session(plan.http, secret) as session:
        result = await session.rpc("tools/call", {"name": plan.remote_tool, "arguments": dict(args)})
    if not isinstance(result, dict):
        raise UpstreamError("the MCP server's answer is not a tool result")
    text, structured = _text_of(result)
    out: dict[str, Any] = {"ok": result.get("isError") is not True, "body": up.redact(text, secret)}
    if structured is not None:
        out["structured"] = json.loads(up.redact(json.dumps(structured), secret))
    return out


async def discover(plan: HttpPlan, credential_ref: str | None) -> list[dict]:
    """The remote server's tools (name, description, inputSchema), at most MAX_IMPORT_TOOLS."""
    secret = _secret(plan, credential_ref)
    tools: list[dict] = []
    async with _Session(plan, secret) as session:
        cursor: str | None = None
        for _ in range(10):
            result = await session.rpc("tools/list", {"cursor": cursor} if cursor else {})
            if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
                raise UpstreamError("the MCP server's tools/list answer is not a tool list")
            tools += [t for t in result["tools"] if isinstance(t, dict)]
            cursor = result.get("nextCursor")
            if not isinstance(cursor, str) or len(tools) >= MAX_IMPORT_TOOLS:
                break
    return tools[:MAX_IMPORT_TOOLS]
