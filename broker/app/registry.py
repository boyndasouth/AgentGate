"""Day 11: the tool registry. Tools are rows in the `tools` table, not Python code.

A row says what a tool's arguments look like (`args_schema`, JSON Schema 2020-12), how risky it
is (`risk_class`), which arguments the policy looks at (`context_map`), whether its output is
untrusted (`taints_session`) and where the call goes (`upstream`). The gate reads all of that
from here; `tools.py` only keeps the mock implementations behind `upstream.kind = "builtin"`,
`upstream.py` forwards `upstream.kind = "http"` rows to a real API (Day 12) and `mcp_upstream.py`
forwards `upstream.kind = "mcp"` rows to a remote MCP server (Day 14).

Safe by default, at every step:
  - a row the broker can't fully understand is kept but marked with a `problem`, and every call
    to it is denied before OpenFGA is asked;
  - arguments must match the schema exactly (unknown arguments are always refused);
  - a `context_map` entry that can't be resolved for a call denies the call. The gate never
    sends OpenFGA a made-up value such as amount 0.

The cache is refreshed whenever the table changes: a statement trigger bumps
`registry_state.version`, and the gate compares that number on every lookup (one primary-key
read). A change found that way is written to the audit log, so an edit made straight in SQL
still leaves a trace.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import logging
import math
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Mapping

import asyncpg
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from referencing import Registry as _RefRegistry

from . import audit, mcp_upstream, tools as builtin, upstream as http_upstream

log = logging.getLogger("agentgate.registry")

TOOL_NAME = re.compile(r"[a-z][a-z0-9_.]{1,63}")
RISK_CLASSES = ("read", "write", "egress", "money", "destructive")
UPSTREAM_KINDS = ("builtin", "http", "mcp")

# context_map keys -> the JSON type the mapped argument must have. Each key feeds one OpenFGA
# condition parameter (the names in policy/model.fga, unchanged since Day 10):
#   amount -> amount    url -> host    recipient -> recipient_domain    payee -> payee
#   invoice -> invoice_matches (looked up in Postgres)
CONTEXT_KEYS: dict[str, tuple[str, ...]] = {
    "amount": ("number", "integer"),
    "url": ("string",),
    "recipient": ("string",),
    "payee": ("string",),
    "invoice": ("string",),
}
# `invoice` may be left out of a call (no invoice = a human decides). The others must be present.
_OPTIONAL_CONTEXT = frozenset({"invoice"})

# Size caps. The request body is capped by the route (MAX_BODY_BYTES); these apply to the
# decoded arguments, whatever the tool's own schema says.
MAX_BODY_BYTES = 64 * 1024
MAX_STRING_CHARS = 16_384
MAX_DEPTH = 8
MAX_VALUES = 1_000

_NO_REMOTE_REFS = _RefRegistry()     # an empty registry: "$ref" can only point inside the schema
_SAFE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,40}")


class ArgsError(Exception):
    """The arguments don't match the tool's schema (HTTP 422). The message never holds a value."""


class ContextError(Exception):
    """The policy context can't be built for this call. The gate denies (fails closed)."""


@dataclass(frozen=True)
class PolicyInputs:
    """What the gate hands to OpenFGA for one call (plus the invoice to look up)."""
    amount: float = 0.0
    host: str = ""
    recipient_domain: str = ""
    payee: str = ""
    invoice_id: str | None = None        # None: this tool has no invoice mapping
    allowlist_reason: str | None = None  # what to say if an allowlisted argument needs a human


@dataclass(frozen=True)
class Tool:
    name: str
    description: str = ""
    risk_class: str = "destructive"
    taints: bool = True                              # returns untrusted outside content
    context_map: Mapping[str, str] = field(default_factory=dict)
    upstream: Mapping[str, Any] = field(default_factory=dict)
    credential_ref: str | None = None
    enabled: bool = False
    version: int = 1
    args_schema: Mapping[str, Any] = field(default_factory=dict)
    arg_order: tuple[str, ...] = ()                  # for the approver's summary in Slack
    defaults: Mapping[str, Any] = field(default_factory=dict)
    problem: str | None = None                       # why this row can't be used; None = fine
    validator: Any = field(default=None, repr=False, compare=False)
    http: Any = field(default=None, repr=False, compare=False)   # upstream.HttpPlan for kind "http"
    mcp: Any = field(default=None, repr=False, compare=False)    # mcp_upstream.McpPlan for kind "mcp" (Day 14)

    @property
    def usable(self) -> bool:
        return self.enabled and self.problem is None

    def unavailable_reason(self) -> str | None:
        """Why a call to this tool is refused before the policy is asked, or None."""
        if not self.enabled:
            return f"tool '{self.name}' is disabled"
        if self.problem:
            return f"tool '{self.name}' is misconfigured in the registry ({self.problem}); failing closed"
        return None

    def public(self) -> dict:
        """Admin view (GET /tools). `credential_ref` is a name, never the secret."""
        return {"name": self.name, "description": self.description, "risk_class": self.risk_class,
                "taints_session": self.taints, "context_map": dict(self.context_map),
                "upstream": dict(self.upstream), "credential_ref": self.credential_ref,
                "enabled": self.enabled, "version": self.version, "args_schema": dict(self.args_schema),
                "problem": self.problem}

    @property
    def kind(self) -> str:
        return str(self.upstream.get("kind", "?"))


# ---------------------------------------------------------------- compiling a row


def _has_remote_ref(node: Any, depth: int = 0) -> bool:
    if depth > 32:
        return True
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("$ref", "$dynamicRef") and not (isinstance(value, str) and value.startswith("#")):
                return True
            if key == "$id" or _has_remote_ref(value, depth + 1):
                return True
    elif isinstance(node, list):
        return any(_has_remote_ref(v, depth + 1) for v in node)
    return False


def _schema_problem(schema: Any) -> str | None:
    if not isinstance(schema, dict):
        return "args_schema is not an object"
    if schema.get("type") != "object":
        return "args_schema.type must be 'object'"
    props = schema.get("properties", {})
    if not isinstance(props, dict) or not all(isinstance(p, dict) for p in props.values()):
        return "args_schema.properties must map argument names to schemas"
    if schema.get("additionalProperties", False) is not False:
        return "args_schema.additionalProperties must be false (unknown arguments are always refused)"
    for banned in ("patternProperties", "unevaluatedProperties", "propertyNames"):
        if banned in schema:
            return f"args_schema.{banned} is not supported at the top level"
    if _has_remote_ref(schema):
        return "args_schema may only use '$ref' inside itself ('#/...'), and no '$id'"
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        return f"args_schema is not valid JSON Schema 2020-12 ({exc.validator or 'schema'} at " \
               f"/{'/'.join(str(p) for p in exc.absolute_path)})"
    return None


def _context_problem(context_map: Any, schema: dict) -> str | None:
    if not isinstance(context_map, dict):
        return "context_map is not an object"
    props, required = schema.get("properties", {}), schema.get("required", [])
    for key, arg in context_map.items():
        if key not in CONTEXT_KEYS:
            return f"context_map key '{key}' is unknown (use {', '.join(CONTEXT_KEYS)})"
        if not isinstance(arg, str) or arg not in props:
            return f"context_map.{key} points to an argument that args_schema doesn't declare"
        if props[arg].get("type") not in CONTEXT_KEYS[key]:
            return f"context_map.{key}: argument '{arg}' must have type {' or '.join(CONTEXT_KEYS[key])}"
        if key not in _OPTIONAL_CONTEXT and arg not in required:
            return f"context_map.{key}: argument '{arg}' must be required"
    return None


def _upstream_problem(name: str, upstream: Any, schema: dict, credential_ref: Any) -> tuple[str | None, Any]:
    """(why the upstream can't be used or None, the compiled plan for an http upstream)."""
    if not isinstance(upstream, dict) or upstream.get("kind") not in UPSTREAM_KINDS:
        return f"upstream.kind must be one of {', '.join(UPSTREAM_KINDS)}", None
    if credential_ref is not None and not isinstance(credential_ref, str):
        return "credential_ref must be a string or null", None
    if upstream["kind"] == "http":      # Day 12
        plan, why = http_upstream.compile_http(upstream, schema, credential_ref)
        return why, plan
    if upstream["kind"] == "mcp":       # Day 14
        plan, why = mcp_upstream.compile_mcp(upstream, schema, credential_ref)
        return why, plan
    if upstream["kind"] != "builtin":
        return f"upstream kind '{upstream['kind']}' is not supported by this broker version", None
    handler = upstream.get("handler", name)
    if not isinstance(handler, str) or handler not in builtin.BUILTINS:
        return "upstream.handler names no built-in implementation", None
    return None, None


def compile_row(row: Mapping[str, Any]) -> Tool:
    """Turn a `tools` row into a Tool. Never raises: a bad row comes back with `problem` set,
    and the gate denies every call to it."""
    name = str(row.get("name", ""))
    schema, context_map, upstream = row.get("args_schema"), row.get("context_map"), row.get("upstream")
    problem, plan = None, None
    if not TOOL_NAME.fullmatch(name):
        problem = "name must match ^[a-z][a-z0-9_.]{1,63}$"
    elif row.get("risk_class") not in RISK_CLASSES:
        problem = f"risk_class must be one of {', '.join(RISK_CLASSES)}"
    else:
        problem = _schema_problem(schema) or _context_problem(context_map, schema)
        if problem is None:
            problem, plan = _upstream_problem(name, upstream, schema, row.get("credential_ref"))

    validator, defaults, order = None, {}, ()
    if problem is None:
        # additionalProperties is forced, not trusted: a row that leaves it out still refuses extras.
        validator = Draft202012Validator({**schema, "additionalProperties": False}, registry=_NO_REMOTE_REFS)
        props, required = schema.get("properties", {}), list(schema.get("required", []))
        # jsonb doesn't keep key order; `required` is an array, so it does.
        order = tuple(required) + tuple(k for k in props if k not in required)
        defaults = {k: p["default"] for k, p in props.items() if "default" in p and k not in required}
        for key, value in defaults.items():
            if not Draft202012Validator(props[key], registry=_NO_REMOTE_REFS).is_valid(value):
                problem, validator = f"the default of argument '{key}' doesn't match its own schema", None
                break

    return Tool(
        name=name, description=str(row.get("description") or ""),
        risk_class=row.get("risk_class") if row.get("risk_class") in RISK_CLASSES else "destructive",
        taints=bool(row.get("taints_session", True)),
        context_map=dict(context_map) if isinstance(context_map, dict) else {},
        upstream=dict(upstream) if isinstance(upstream, dict) else {},
        credential_ref=row.get("credential_ref"), enabled=bool(row.get("enabled", False)),
        version=int(row.get("version") or 1), args_schema=schema if isinstance(schema, dict) else {},
        arg_order=order, defaults=defaults, problem=problem, validator=validator,
        http=plan if problem is None and isinstance(plan, http_upstream.HttpPlan) else None,
        mcp=plan if problem is None and isinstance(plan, mcp_upstream.McpPlan) else None)


# ---------------------------------------------------------------- validating one call


def _check_size(node: Any, depth: int = 0, seen: list[int] | None = None) -> None:
    seen = seen if seen is not None else [0]
    seen[0] += 1
    if seen[0] > MAX_VALUES:
        raise ArgsError(f"too many values (more than {MAX_VALUES})")
    if depth > MAX_DEPTH:
        raise ArgsError(f"nested deeper than {MAX_DEPTH} levels")
    if isinstance(node, str):
        if len(node) > MAX_STRING_CHARS:
            raise ArgsError(f"a string is longer than {MAX_STRING_CHARS} characters")
    elif isinstance(node, dict):
        for key, value in node.items():
            if len(key) > 256:
                raise ArgsError("an argument name is longer than 256 characters")
            _check_size(value, depth + 1, seen)
    elif isinstance(node, list):
        for value in node:
            _check_size(value, depth + 1, seen)


def _name(part: Any) -> str:
    """Argument names come from the caller: only plain ones are repeated into the audit log."""
    text = str(part)
    return text if _SAFE_NAME.fullmatch(text) else "?"


def _describe(error: Any, props: Mapping[str, Any]) -> str:
    """One validation error as text. Never includes a value: the reason goes into the audit log,
    where arguments are only kept as an HMAC."""
    where = ".".join(_name(p) for p in error.absolute_path)
    if error.validator == "additionalProperties" and not error.absolute_path:
        extra = sorted(k for k in error.instance if k not in props)
        shown = ", ".join(f"'{_name(k)}'" for k in extra[:3])
        return f"unexpected argument{'s' if len(extra) > 1 else ''} {shown}" + (" ..." if len(extra) > 3 else "")
    if error.validator == "required":
        missing = [r for r in error.validator_value if r not in error.instance]
        at = f" in '{where}'" if where else ""
        return f"missing required argument {', '.join(repr(_name(m)) for m in missing[:3])}{at}"
    if error.validator == "type":
        want = error.validator_value
        want = " or ".join(want) if isinstance(want, list) else str(want)
        return f"argument '{where}' must be of type {want}" if where else f"arguments must be of type {want}"
    return f"argument '{where or '?'}' fails the '{_name(error.validator)}' rule of the tool's schema"


def validate(tool: Tool, raw: Any) -> dict:
    """Check raw JSON arguments against the tool's schema and fill in schema defaults.
    Returns a new dict; raises ArgsError. The caller must have checked `tool.usable`."""
    if tool.validator is None:
        raise ArgsError("the tool has no usable schema")
    _check_size(raw)
    errors = sorted(tool.validator.iter_errors(raw), key=lambda e: (len(e.absolute_path), str(e.validator)))
    if errors:
        raise ArgsError(_describe(errors[0], tool.args_schema.get("properties", {})))
    args = dict(raw)
    for key, value in tool.defaults.items():
        args.setdefault(key, copy.deepcopy(value))
    if tool.http is not None:
        # Day 12: an argument that goes into the upstream URL must be usable as one path segment.
        try:
            http_upstream.check_path_args(tool.http, args)
        except http_upstream.PathArgError as exc:
            raise ArgsError(str(exc)) from None
    return args


# ---------------------------------------------------------------- policy context


def policy_safe(value: str) -> str:
    """Day 9: OpenFGA rejects a check whose context holds a control character (newline, tab,
    U+0000-U+001F, U+007F-U+009F), and the gate would then fail closed with a misleading
    "policy engine unavailable". Such a value can't be on any allowlist, so it becomes ''."""
    return "" if any(unicodedata.category(c) == "Cc" for c in value) else value


def host_of(url: str) -> str:
    """Day 7 (G03): the URL's hostname for OpenFGA's `host` context, lowercased, trailing dot
    dropped. urlsplit takes the real host from tricks like https://example.com@evil.example/.
    '' for non-http(s) schemes and unparseable URLs; a tainted session can never match ''
    against the allowlist, so those fail closed."""
    try:
        parts = urllib.parse.urlsplit(url.strip())
        if parts.scheme.lower() not in ("http", "https"):
            return ""
        return policy_safe((parts.hostname or "").rstrip("."))
    except ValueError:
        return ""


# One plain ASCII address, nothing else: no display name, no list, no comments, no quoting.
_PLAIN_ADDRESS = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


def recipient_domain_of(recipient: str) -> str:
    """Day 8 (G01): the recipient's domain for OpenFGA's `recipient_domain` context, lowercased.
    '' for anything that isn't exactly one plain address ("a@x, b@y", "Name <a@x>", non-ASCII
    look-alikes, a trailing dot). '' is never on an allowlist, so an address the gate can't
    read with certainty goes to a human."""
    # No strip(): the tool gets the argument as sent, so the gate must judge it as sent.
    m = _PLAIN_ADDRESS.fullmatch(recipient)
    return m.group(1).lower() if m else ""


def policy_inputs(tool: Tool, args: Mapping[str, Any]) -> PolicyInputs:
    """Build the OpenFGA context for one call from the tool's `context_map`. `args` are the
    validated arguments. Raises ContextError when a mapped argument is missing or has the wrong
    type: compile_row already rules that out, so this is the second lock on the same door."""
    values: dict[str, Any] = {}
    for key, arg in tool.context_map.items():
        if arg not in args:
            if key in _OPTIONAL_CONTEXT:
                values[key] = ""
                continue
            raise ContextError(f"context_map.{key} points to argument '{_name(arg)}', which this call doesn't have")
        value = args[arg]
        if key == "amount":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ContextError(f"argument '{_name(arg)}' is not a number")
            try:
                value = float(value)
            except OverflowError:
                value = math.inf
            if not math.isfinite(value):
                raise ContextError(f"argument '{_name(arg)}' is not a finite number")
        elif not isinstance(value, str):
            raise ContextError(f"argument '{_name(arg)}' is not a string")
        values[key] = value

    reason = None
    domain = recipient_domain_of(values["recipient"]) if "recipient" in values else ""
    if "recipient" in values:
        # Account numbers stay out of the reason (it goes into the audit log, where arguments are
        # kept only as an HMAC); the approver sees the full arguments in Slack. A domain is fine.
        reason = f"recipient domain '{domain}' is not on the allowlist" if domain else "recipient is not one plain address"
    elif "payee" in values:
        reason = "payee is not on the allowlist"
    return PolicyInputs(
        amount=values.get("amount", 0.0),
        host=host_of(values["url"]) if "url" in values else "",
        recipient_domain=domain,
        # The payee is judged exactly as sent: no trimming, no case folding (Day 9).
        payee=policy_safe(values["payee"]) if "payee" in values else "",
        invoice_id=values.get("invoice"),
        allowlist_reason=reason)


# ---------------------------------------------------------------- running


async def run(tool: Tool, args: dict) -> dict:
    """Call the tool's upstream: a built-in mock, or (Day 12) a real HTTP API. For http the
    result is {"status", "ok", "body"}; upstream.UpstreamError means there was no usable answer.
    Other kinds never get here: compile_row marks them unusable."""
    if tool.http is not None:
        return await http_upstream.call(tool.http, tool.credential_ref, args)
    if tool.mcp is not None:     # Day 14: {"ok", "body"} from the remote MCP server
        return await mcp_upstream.call(tool.mcp, tool.credential_ref, args)
    handler = builtin.BUILTINS[tool.upstream.get("handler", tool.name)]
    return await handler(args)


def tx_id_of(result: Any) -> str:
    """The payment reference in a tool's result, for the invoice record ('' if there is none)."""
    if isinstance(result, dict):
        body = result.get("body")
        for holder in (result, body if isinstance(body, dict) else {}):
            if isinstance(holder.get("tx_id"), str):
                return holder["tx_id"][:200]
    return ""


# ---------------------------------------------------------------- the cache

_COLUMNS = ("name, description, args_schema, risk_class, context_map, taints_session, upstream, "
            "credential_ref, enabled, version")
_SCALARS = (("enabled", "enabled"), ("taints_session", "taints"), ("risk_class", "risk_class"))
_OPAQUE = (("args_schema", "args_schema"), ("context_map", "context_map"), ("upstream", "upstream"),
           ("credential_ref", "credential_ref"), ("description", "description"))


def _diff(old: Tool, new: Tool) -> str | None:
    """What changed between two versions of a row, for the audit log. Values of the small flags
    are shown; schemas, mappings and credential names are only named."""
    parts = [f"{label} {getattr(old, attr)!s} -> {getattr(new, attr)!s}".lower()
             for label, attr in _SCALARS if getattr(old, attr) != getattr(new, attr)]
    parts += [f"{label} changed" for label, attr in _OPAQUE if getattr(old, attr) != getattr(new, attr)]
    if not parts and old.version == new.version:
        return None
    return f"{'; '.join(parts) or 'no field changed'} (version {old.version} -> {new.version})"


class Registry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        self._version: int | None = None
        self._lock = asyncio.Lock()

    # -- reads that never touch the database (Slack summaries, GET /agents) --

    def peek(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def all(self) -> list[Tool]:
        return [self._tools[k] for k in sorted(self._tools)]

    # -- reads that first make sure the cache matches the table --

    async def get(self, conn: asyncpg.Connection, name: str) -> Tool | None:
        await self.sync(conn)
        return self._tools.get(name)

    async def sync(self, conn: asyncpg.Connection) -> None:
        """Reload if the table changed since the last load. Raises on a database error, so the
        caller fails closed: the gate never decides on a registry it couldn't check."""
        version = await conn.fetchval("SELECT version FROM registry_state WHERE id")
        if version is not None and version == self._version:
            return
        async with self._lock:
            if version is not None and version == self._version:
                return
            await self.load(conn, record_changes=self._version is not None)

    @contextlib.asynccontextmanager
    async def changing(self, conn: asyncpg.Connection, actor: str):
        """Day 12: wrap a write to the `tools` table made through the admin API. The reload that
        follows records the change with WHO made it. Holding the lock keeps a concurrent lookup
        from recording the same change first, without the name."""
        async with self._lock:
            if self._version is None:
                await self.load(conn)
            yield
            await self.load(conn, record_changes=True, actor=actor)

    async def load(self, conn: asyncpg.Connection, *, record_changes: bool = False,
                   actor: str | None = None) -> None:
        # The version is read BEFORE the rows. If a row changes in between, the stored number is
        # already stale and the next lookup loads again.
        version = await conn.fetchval("SELECT version FROM registry_state WHERE id")
        rows = await conn.fetch(f"SELECT {_COLUMNS} FROM tools ORDER BY name")
        new = {r["name"]: compile_row(dict(r)) for r in rows}
        old, self._tools, self._version = self._tools, new, version
        for tool in new.values():
            if tool.problem and (tool.name not in old or old[tool.name].problem != tool.problem):
                log.warning("tool '%s' is unusable: %s", tool.name, tool.problem)
        if not record_changes:
            return
        changes: list[tuple[str, str]] = []
        for name in sorted(set(old) | set(new)):
            if name not in new:
                changes.append((name, "tool removed from the registry"))
            elif name not in old:
                t = new[name]
                changes.append((name, f"tool added: risk {t.risk_class}, {'enabled' if t.enabled else 'disabled'}, "
                                      f"taints_session {str(t.taints).lower()}, upstream {t.upstream.get('kind', '?')}"))
            else:
                what = _diff(old[name], new[name])
                if what:
                    changes.append((name, what))
        for name, what in changes:
            # A tool name from a row that failed the name check could be anything: don't repeat it.
            await audit.append_event(conn, event_type="registry_changed", decision="info", approver=actor,
                                     tool=name if TOOL_NAME.fullmatch(name) else None, reason=what[:300])


REGISTRY = Registry()
