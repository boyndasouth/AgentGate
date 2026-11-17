"""Day 12: forwarding an allowed call to a real HTTP API (`upstream.kind = "http"`).

The broker is the only path to the upstream: it holds the credential, the agent never sees it.
A registry row describes the request:

    {"kind": "http", "method": "POST",
     "url": "https://crm.example.com/api/tickets/{ticket_id}",   # {arg} only in the path
     "headers": {"Accept": "application/json"},                  # static, never from arguments
     "auth": {"type": "bearer"},            # or {"type": "header", "name": "X-Api-Key"}, {"type": "none"}
     "send_args": "json",                   # or "query"; default: query for GET/DELETE, json otherwise
     "timeout_seconds": 10, "max_response_bytes": 262144}

and `credential_ref` names the env var that holds the secret (it must start with UPSTREAM_, so a
row can never point at the broker's own keys or DATABASE_URL).

What this module refuses, at load time (the row is then unusable) or at call time:
  - a host taken from an argument: placeholders are allowed in the path only, and each value is
    percent-encoded as ONE path segment ('/', '..' and control characters can't change the route);
  - plain http, and hosts that resolve to a private, loopback or link-local address, unless the
    host is listed in UPSTREAM_PRIVATE_HOSTS (the local mock upstream). The address is resolved
    once, checked, and the connection goes to exactly that address, so a DNS answer that changes
    between the check and the connect can't redirect the call (and the credential);
  - redirects: never followed, a 3xx is an error;
  - slow or huge answers: a timeout and a size cap, applied while reading.

The credential never leaves this module except inside the outgoing request: results are
scrubbed of it before they are returned (an upstream that echoes its request headers would
otherwise hand it to the agent), and error texts are written here, never copied from a library.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import re
import socket
import ssl
import urllib.parse
from dataclasses import dataclass
from typing import Any, Mapping

import httpx

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
CREDENTIAL_REF = re.compile(r"UPSTREAM_[A-Z0-9_]{1,64}")
PRIVATE_HOSTS_ENV = "UPSTREAM_PRIVATE_HOSTS"     # not a credential: a comma-separated host list

DEFAULT_TIMEOUT, MAX_TIMEOUT = 10.0, 30.0
DEFAULT_MAX_BYTES, MAX_MAX_BYTES = 256 * 1024, 1024 * 1024
MIN_SECRET_CHARS = 8
REDACTED = "[redacted]"

_KEYS = {"kind", "method", "url", "headers", "auth", "send_args", "timeout_seconds", "max_response_bytes"}
_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]{0,63})\}")
_PATH_LITERAL = re.compile(r"[A-Za-z0-9._~!$&'()*+,;=:@/%-]*")
_HOST = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*")
_HEADER_NAME = re.compile(r"[A-Za-z0-9-]{1,64}")
_HEADER_VALUE = re.compile(r"[\x20-\x7e]{0,1024}")
_SECRET = re.compile(r"[\x21-\x7e]+")              # printable ASCII, no spaces: safe in a header
# Headers a row may not set: they belong to the connection, or carry credentials.
_RESERVED = {"host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer",
             "authorization", "proxy-authorization", "cookie", "content-type"}
_UNUSABLE_AUTH_HEADERS = _RESERVED - {"authorization"}


class UpstreamError(Exception):
    """The call was allowed but the upstream could not be reached or gave an unusable answer.
    The message is safe to show to the agent and to store in the audit log."""


class PathArgError(ValueError):
    """An argument can't be placed into the URL path. Raised before the policy is asked."""


@dataclass(frozen=True)
class HttpPlan:
    """A registry row's `upstream`, checked and taken apart once, at load time."""
    method: str
    scheme: str
    host: str
    port: int
    path: str                        # still holds its {placeholders}
    query: str                       # static query string from the row, may be ''
    path_args: tuple[str, ...]
    headers: tuple[tuple[str, str], ...]
    auth: str                        # 'none' | 'bearer' | 'header'
    auth_header: str
    auth_prefix: str
    send_args: str                   # 'json' | 'query'
    timeout: float
    max_bytes: int
    private_ok: bool                 # host is in UPSTREAM_PRIVATE_HOSTS

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.host}" + ("" if self.port == _default_port(self.scheme) else f":{self.port}")


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def private_hosts(env: Mapping[str, str] | None = None) -> frozenset[str]:
    raw = (env if env is not None else os.environ).get(PRIVATE_HOSTS_ENV, "")
    return frozenset(h.strip().lower() for h in raw.split(",") if h.strip())


def _public_address(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def credential_problem(credential_ref: Any, env: Mapping[str, str] | None = None) -> str | None:
    """Why the named credential can't be used, or None. Never says anything about its value."""
    if not isinstance(credential_ref, str) or not CREDENTIAL_REF.fullmatch(credential_ref):
        return "credential_ref must be the name of an env var matching ^UPSTREAM_[A-Z0-9_]{1,64}$"
    if credential_ref == PRIVATE_HOSTS_ENV:
        return f"credential_ref can't be {PRIVATE_HOSTS_ENV}"
    secret = (env if env is not None else os.environ).get(credential_ref, "")
    if not secret:
        return f"credential_ref '{credential_ref}' is not set in the broker's environment"
    if len(secret) < MIN_SECRET_CHARS or not _SECRET.fullmatch(secret):
        return (f"the value of '{credential_ref}' can't be used as a credential (it needs at least "
                f"{MIN_SECRET_CHARS} printable characters and no spaces)")
    return None


def compile_http(upstream: Mapping[str, Any], schema: Mapping[str, Any], credential_ref: Any,
                 env: Mapping[str, str] | None = None) -> tuple[HttpPlan | None, str | None]:
    """Check an http `upstream` against the tool's argument schema. Returns (plan, None) or
    (None, why it can't be used). Never raises."""
    unknown = sorted(set(upstream) - _KEYS)
    if unknown:
        return None, f"upstream has an unknown key ({', '.join(str(k)[:40] for k in unknown[:3])})"
    method = upstream.get("method")
    if method not in METHODS:
        return None, f"upstream.method must be one of {', '.join(METHODS)}"

    url = upstream.get("url")
    if not isinstance(url, str) or not url or len(url) > 2048 or any(ord(c) < 0x21 or ord(c) > 0x7e for c in url):
        return None, "upstream.url must be a URL in printable ASCII (at most 2048 characters)"
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return None, "upstream.url can't be parsed"
    scheme, host = parts.scheme.lower(), (parts.hostname or "").lower()
    if scheme not in ("http", "https"):
        return None, "upstream.url must start with https://"
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        return None, "upstream.url must not carry a user name or password (use credential_ref)"
    if parts.fragment or "#" in url:
        return None, "upstream.url must not have a fragment"
    if "{" in parts.netloc or "}" in parts.netloc or "{" in parts.query or "}" in parts.query:
        return None, "upstream.url may use {argument} placeholders in the path only, never in the host or query"
    is_ip = True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        is_ip = False
    if not host or (not is_ip and not _HOST.fullmatch(host)):
        return None, "upstream.url has no valid host name"
    private_ok = host in private_hosts(env)
    if scheme != "https" and not private_ok:
        return None, f"upstream.url must use https (plain http is only allowed for hosts in {PRIVATE_HOSTS_ENV})"
    if is_ip and not private_ok and not _public_address(host):
        return None, f"upstream.url points at a private or reserved address (not in {PRIVATE_HOSTS_ENV})"

    path = parts.path or "/"
    path_args = tuple(dict.fromkeys(_PLACEHOLDER.findall(path)))
    if not _PATH_LITERAL.fullmatch(_PLACEHOLDER.sub("", path)):
        return None, "upstream.url path has characters that aren't allowed (or a malformed {placeholder})"
    props, required = schema.get("properties", {}), schema.get("required", [])
    for arg in path_args:
        if arg not in props or arg not in required or props[arg].get("type") not in ("string", "integer"):
            return None, (f"upstream.url placeholder '{{{arg}}}' must name a required argument of type "
                          "string or integer")

    headers = upstream.get("headers", {})
    if not isinstance(headers, dict) or len(headers) > 20:
        return None, "upstream.headers must be an object with at most 20 entries"
    for name, value in headers.items():
        if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name) or name.lower() in _RESERVED:
            return None, "upstream.headers has a name that isn't allowed (reserved, or not a plain header name)"
        if not isinstance(value, str) or not _HEADER_VALUE.fullmatch(value):
            return None, f"upstream.headers.{name} must be a printable ASCII string"

    auth = upstream.get("auth")
    if auth is None:
        auth = {"type": "bearer"} if credential_ref else {"type": "none"}
    if not isinstance(auth, dict) or auth.get("type") not in ("none", "bearer", "header") \
            or set(auth) - {"type", "name", "prefix"}:
        return None, "upstream.auth must be {\"type\": \"bearer\"}, {\"type\": \"header\", \"name\": ...} or {\"type\": \"none\"}"
    auth_type, auth_header, auth_prefix = auth["type"], "", ""
    if auth_type == "bearer":
        auth_header, auth_prefix = "Authorization", "Bearer "
    elif auth_type == "header":
        auth_header, auth_prefix = auth.get("name"), auth.get("prefix", "")
        if not isinstance(auth_header, str) or not _HEADER_NAME.fullmatch(auth_header) \
                or auth_header.lower() in _UNUSABLE_AUTH_HEADERS:
            return None, "upstream.auth.name must be a plain header name"
        if not isinstance(auth_prefix, str) or len(auth_prefix) > 32 or not _HEADER_VALUE.fullmatch(auth_prefix):
            return None, "upstream.auth.prefix must be a short printable string"
        if any(name.lower() == auth_header.lower() for name in headers):
            return None, "upstream.headers must not set the header that carries the credential"
    if auth_type == "none":
        if credential_ref:
            return None, "credential_ref is set but upstream.auth.type is 'none'"
    else:
        why = credential_problem(credential_ref, env)
        if why:
            return None, why

    send_args = upstream.get("send_args", "query" if method in ("GET", "DELETE") else "json")
    if send_args not in ("json", "query") or (send_args == "json" and method == "GET"):
        return None, "upstream.send_args must be 'json' or 'query' (GET sends its arguments in the query)"
    timeout = upstream.get("timeout_seconds", DEFAULT_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= MAX_TIMEOUT:
        return None, f"upstream.timeout_seconds must be a number from 1 to {MAX_TIMEOUT:g}"
    max_bytes = upstream.get("max_response_bytes", DEFAULT_MAX_BYTES)
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= MAX_MAX_BYTES:
        return None, f"upstream.max_response_bytes must be an integer from 1 to {MAX_MAX_BYTES}"

    return HttpPlan(method=method, scheme=scheme, host=host, port=port or _default_port(scheme), path=path,
                    query=parts.query, path_args=path_args, headers=tuple(sorted(headers.items())),
                    auth=auth_type, auth_header=auth_header or "", auth_prefix=auth_prefix,
                    send_args=send_args, timeout=float(timeout), max_bytes=max_bytes, private_ok=private_ok), None


# ---------------------------------------------------------------- one call


def _segment(name: str, value: Any) -> str:
    """One argument as exactly one URL path segment."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise PathArgError(f"argument '{name}' can't be used in the upstream URL (it must be a string or an integer)")
    text = str(value)
    if not text or len(text) > 256 or text in (".", "..") or any(ord(c) < 0x20 or ord(c) == 0x7f for c in text):
        raise PathArgError(f"argument '{name}' can't be used in the upstream URL "
                           "(empty, too long, '.', '..' or a control character)")
    return urllib.parse.quote(text, safe="")


def check_path_args(plan: HttpPlan, args: Mapping[str, Any]) -> None:
    """Raises PathArgError if an argument can't go into the path. Called with the validated
    arguments, before the policy decision, so a bad value is an ordinary 422."""
    for name in plan.path_args:
        _segment(name, args.get(name))


def _query_pairs(args: Mapping[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for key, value in args.items():
        for item in (value if isinstance(value, list) else [value]):
            if item is None:
                continue
            if isinstance(item, bool):
                item = "true" if item else "false"
            elif isinstance(item, (dict, list)):
                item = json.dumps(item, separators=(",", ":"))
            out.append((key, str(item)))
    return out


def redact(text: str, secret: str) -> str:
    """Remove the credential from upstream output, in the forms an echo would carry it."""
    if not secret:
        return text
    forms = {secret, urllib.parse.quote(secret, safe=""), json.dumps(secret)[1:-1],
             base64.b64encode(secret.encode()).decode()}
    for form in sorted(forms, key=len, reverse=True):
        text = text.replace(form, REDACTED)
    return text


_client: httpx.AsyncClient | None = None


def _http() -> httpx.AsyncClient:
    global _client
    if _client is None:
        # trust_env=False: no proxy from the environment may sit between the broker and the
        # upstream. No keep-alive: connections go to a pinned address with the host name given
        # separately, and must never be reused for a different host on the same address.
        _client = httpx.AsyncClient(follow_redirects=False, trust_env=False, verify=ssl.create_default_context(),
                                    limits=httpx.Limits(max_keepalive_connections=0, max_connections=20),
                                    headers={"User-Agent": "AgentGate-broker"})
    return _client


async def close() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


async def _resolve(plan: HttpPlan) -> str:
    """The address to connect to. Every address the name resolves to must be public, unless the
    host is in UPSTREAM_PRIVATE_HOSTS."""
    try:
        async with asyncio.timeout(min(plan.timeout, 5.0)):
            infos = await asyncio.get_running_loop().getaddrinfo(plan.host, plan.port, type=socket.SOCK_STREAM)
    except TimeoutError:
        raise UpstreamError("the upstream host name could not be resolved in time") from None
    except (OSError, UnicodeError):
        raise UpstreamError("the upstream host name could not be resolved") from None
    addrs = list(dict.fromkeys(info[4][0] for info in infos))
    if not addrs:
        raise UpstreamError("the upstream host name could not be resolved")
    if not plan.private_ok and not all(_public_address(a) for a in addrs):
        raise UpstreamError("the upstream host resolves to a private or reserved address; not connecting")
    return addrs[0]


async def call(plan: HttpPlan, credential_ref: str | None, args: Mapping[str, Any]) -> dict:
    """Send one allowed call to the upstream and return {"status", "ok", "body"}, scrubbed of
    the credential. Raises UpstreamError (safe text) when there is no usable answer."""
    secret = ""
    if plan.auth != "none":
        if credential_problem(credential_ref):
            raise UpstreamError("the upstream credential is not available in the broker's environment")
        secret = os.environ[credential_ref]

    try:
        path = _PLACEHOLDER.sub(lambda m: _segment(m.group(1), args.get(m.group(1))), plan.path)
    except PathArgError as exc:
        raise UpstreamError(str(exc)) from None
    rest = {k: v for k, v in args.items() if k not in plan.path_args}
    query = plan.query
    content = None
    headers = dict(plan.headers)
    if plan.send_args == "query":
        extra = urllib.parse.urlencode(_query_pairs(rest))
        query = "&".join(q for q in (query, extra) if q)
    else:
        content = json.dumps(rest, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    if secret:
        headers[plan.auth_header] = plan.auth_prefix + secret

    addr = await _resolve(plan)
    literal = f"[{addr.split('%')[0]}]" if ":" in addr else addr
    url = f"{plan.scheme}://{literal}:{plan.port}{path}" + (f"?{query}" if query else "")
    headers["Host"] = plan.host if plan.port == _default_port(plan.scheme) else f"{plan.host}:{plan.port}"
    # TLS: the certificate is checked against the host NAME, while the socket goes to `addr`.
    extensions = {"sni_hostname": plan.host} if plan.scheme == "https" else {}
    timeout = httpx.Timeout(plan.timeout, connect=min(plan.timeout, 5.0))

    try:
        async with asyncio.timeout(plan.timeout):
            async with _http().stream(plan.method, url, headers=headers, content=content, timeout=timeout,
                                      extensions=extensions) as resp:
                if 300 <= resp.status_code < 400:
                    raise UpstreamError(f"the upstream answered {resp.status_code} (a redirect); "
                                        "redirects are never followed")
                chunks, size = [], 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > plan.max_bytes:
                        raise UpstreamError(f"the upstream's answer is larger than {plan.max_bytes} bytes")
                    chunks.append(chunk)
                status, ctype = resp.status_code, resp.headers.get("content-type", "")
    except UpstreamError:
        raise
    except (TimeoutError, httpx.TimeoutException):
        raise UpstreamError(f"the upstream did not answer within {plan.timeout:g} s") from None
    except httpx.ConnectError:
        raise UpstreamError("could not connect to the upstream (network or TLS error)") from None
    except httpx.HTTPError as exc:
        raise UpstreamError(f"the upstream request failed ({type(exc).__name__})") from None

    text = redact(b"".join(chunks).decode("utf-8", errors="replace"), secret)
    body: Any = text
    if "json" in ctype.lower():
        try:
            body = json.loads(text)
        except (ValueError, RecursionError):
            body = text
    return {"status": status, "ok": 200 <= status < 300, "body": body}
