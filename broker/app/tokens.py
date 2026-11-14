"""Agent tokens: Ed25519-signed JWTs (alg EdDSA), 10-minute lifetime,
bound to one agent (sub), one session (sid) and one task (tid).

PyJWT handles signing and the standard checks (exp, nbf, iss, aud);
revocation is checked against Postgres on every call.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import asyncpg
import jwt

from .config import Settings
from .keys import SigningKey


class TokenError(Exception):
    """Invalid, expired or revoked token -> 401."""


@dataclass(frozen=True)
class AgentClaims:
    agent_id: str
    session_id: str
    task_id: str
    scopes: frozenset[str]
    jti: str
    issued_at: int
    expires_at: int


def issue_token(
    key: SigningKey, settings: Settings, *, agent_id: str, session_id: str, task_id: str, scopes: list[str]
) -> tuple[str, dict]:
    now = int(time.time())
    claims = {
        "iss": settings.issuer,
        "aud": settings.audience,
        "sub": agent_id,
        "sid": session_id,
        "tid": task_id,
        "scope": " ".join(sorted(scopes)),   # OAuth-style space-separated scopes
        "jti": str(uuid.uuid4()),
        "iat": now,
        "nbf": now,
        "exp": now + settings.token_ttl_seconds,
    }
    token = jwt.encode(claims, key.private_key, algorithm="EdDSA", headers={"kid": key.kid})
    return token, claims


def decode_token(key: SigningKey, settings: Settings, token: str) -> AgentClaims:
    try:
        claims = jwt.decode(
            token,
            key.public_key,
            algorithms=["EdDSA"],               # never accept 'none' or HS*
            audience=settings.audience,
            issuer=settings.issuer,
            options={"require": ["exp", "iat", "nbf", "sub", "jti", "aud", "iss"]},
            leeway=5,
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError(f"invalid token: {exc}") from exc
    try:
        return AgentClaims(
            agent_id=claims["sub"],
            session_id=claims["sid"],
            task_id=claims["tid"],
            scopes=frozenset(claims.get("scope", "").split()),
            jti=claims["jti"],
            issued_at=int(claims["iat"]),
            expires_at=int(claims["exp"]),
        )
    except KeyError as exc:
        raise TokenError(f"token missing claim {exc}") from exc


async def check_not_revoked(conn: asyncpg.Connection, claims: AgentClaims) -> None:
    """Kill switch + single-token revocation. Also rejects tokens of disabled agents."""
    row = await conn.fetchrow(
        """
        SELECT
          (SELECT status FROM agents WHERE id = $1) AS agent_status,
          EXISTS (
            SELECT 1 FROM revocations
            WHERE jti = $2::uuid
               OR (agent_id = $1 AND revoked_at >= $3)
          ) AS revoked
        """,
        claims.agent_id,
        claims.jti,
        datetime.fromtimestamp(claims.issued_at, tz=timezone.utc),
    )
    if row["agent_status"] is None:
        raise TokenError("unknown agent")
    if row["agent_status"] != "active":
        raise TokenError("agent disabled by kill switch")
    if row["revoked"]:
        raise TokenError("token revoked")
