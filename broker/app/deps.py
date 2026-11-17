"""Pieces shared by the route modules (main.py, admin_api.py): guards, the per-request
connection, the JSON response helper and (Day 12) who an admin request acts as."""

from __future__ import annotations

import hmac
import re
from collections.abc import AsyncGenerator
from typing import Any

import asyncpg
from litestar import Request, Response
from litestar.connection import ASGIConnection
from litestar.datastructures import State
from litestar.exceptions import NotAuthorizedException
from litestar.handlers.base import BaseRouteHandler


async def provide_conn(state: State) -> AsyncGenerator[asyncpg.Connection, None]:
    async with state.pool.acquire() as conn:
        yield conn


def _key_guard(header: str, setting: str):
    def guard(connection: ASGIConnection, _: BaseRouteHandler) -> None:
        supplied = connection.headers.get(header, "")
        expected = getattr(connection.app.state.settings, setting)
        if not supplied or not hmac.compare_digest(supplied, expected):
            raise NotAuthorizedException(f"missing or wrong {header}")
    return guard


admin_guard = _key_guard("x-admin-key", "admin_api_key")             # TODO(Day 6): Auth0 login
orchestrator_guard = _key_guard("x-orchestrator-key", "orchestrator_api_key")


def _json(status: int, body: Any) -> Response:
    return Response(content=body, status_code=status)


# The admin key holder may only label an action as coming from the admin UI, never as
# 'slack:...' or 'timeout'. Auth0 subs look like 'auth0|64f0...' or 'google-oauth2|1234'.
VIA = re.compile(r"admin-ui:[A-Za-z0-9|._@-]{1,100}")
VIA_HEADER = "x-admin-via"


class BadVia(Exception):
    """The X-Admin-Via header is present but malformed (HTTP 400)."""


def actor_of(request: Request) -> str:
    """Who an admin request is recorded as in the audit log (Day 12). The admin UI's server sends
    `X-Admin-Via: admin-ui:<Auth0 sub>` from its session; without the header it is 'admin-api'
    (curl, scripts). Same rule as the `via` field of an approval decision (Day 8)."""
    via = request.headers.get(VIA_HEADER)
    if via is None:
        return "admin-api"
    if not VIA.fullmatch(via):
        raise BadVia("X-Admin-Via must look like 'admin-ui:<Auth0 sub>'")
    return via
