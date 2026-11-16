"""Agent tokens: Ed25519-signed JWTs (alg EdDSA), 10-minute lifetime,
bound to one agent (sub), one session (sid) and one task (tid).

Day 10, delegated tokens (RFC 8693 token exchange): `sub` is the agent whose access is used
(the principal), `act` names the agent actually calling, nested once more for a second hop
(`{"sub": "C", "act": {"sub": "B"}}`), and `dlg` lists the delegation ids, root first. The gate
judges the call AS `sub`; kill switch, revocation and audit cover every agent in the chain.

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
    agent_id: str                    # who is calling (the actor; for a plain token, the agent itself)
    session_id: str
    task_id: str
    scopes: frozenset[str]
    jti: str
    issued_at: int
    expires_at: int
    principal: str = ""              # whose access is used: = agent_id unless delegated
    actors: tuple[str, ...] = ()     # delegated only: calling agent first, then earlier hops
    delegation_ids: tuple[str, ...] = ()   # delegated only: root first

    @property
    def delegated(self) -> bool:
        return bool(self.delegation_ids)

    @property
    def chain(self) -> tuple[str, ...]:
        """Every agent this token depends on: principal, then each hop."""
        return (self.principal, *reversed(self.actors)) if self.delegated else (self.agent_id,)


def issue_token(
    key: SigningKey, settings: Settings, *, agent_id: str, session_id: str, task_id: str, scopes: list[str],
    principal: str | None = None, actors: list[str] | None = None, delegation_ids: list[str] | None = None,
    expires_at: int | None = None,
) -> tuple[str, dict]:
    """Plain token: sub = agent_id. Delegated (Day 10): sub = principal, act = actors (calling
    agent first, nested), dlg = delegation ids; expiry capped at `expires_at`."""
    now = int(time.time())
    exp = now + settings.token_ttl_seconds
    if expires_at is not None:
        exp = min(exp, expires_at)
    claims = {
        "iss": settings.issuer,
        "aud": settings.audience,
        "sub": principal if delegation_ids else agent_id,
        "sid": session_id,
        "tid": task_id,
        "scope": " ".join(sorted(scopes)),   # OAuth-style space-separated scopes
        "jti": str(uuid.uuid4()),
        "iat": now,
        "nbf": now,
        "exp": exp,
    }
    if delegation_ids:
        act: dict | None = None
        for actor in reversed(actors or []):      # innermost (earliest hop) first
            act = {"sub": actor, **({"act": act} if act else {})}
        claims["act"] = act
        claims["dlg"] = list(delegation_ids)
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
        actors: list[str] = []
        act = claims.get("act")
        while isinstance(act, dict) and len(actors) < 3:
            actors.append(str(act["sub"]))
            act = act.get("act")
        dlg = claims.get("dlg") or []
        # A delegated token needs both, and one actor per hop; anything else is malformed.
        if bool(actors) != bool(dlg) or (dlg and (not isinstance(dlg, list) or len(dlg) != len(actors)
                                                 or len(dlg) > 2 or act is not None)):
            raise TokenError("invalid token: malformed delegation claims")
        return AgentClaims(
            agent_id=actors[0] if actors else claims["sub"],
            session_id=claims["sid"],
            task_id=claims["tid"],
            scopes=frozenset(claims.get("scope", "").split()),
            jti=claims["jti"],
            issued_at=int(claims["iat"]),
            expires_at=int(claims["exp"]),
            principal=claims["sub"],
            actors=tuple(actors),
            delegation_ids=tuple(str(d) for d in dlg),
        )
    except (KeyError, TypeError) as exc:
        raise TokenError(f"token missing claim {exc}") from exc


async def check_not_revoked(conn: asyncpg.Connection, claims: AgentClaims) -> None:
    """Kill switch + single-token revocation. Also rejects tokens of disabled agents.
    Day 10: for a delegated token, EVERY agent in the chain must be active and not killed
    since the token was issued, and no delegation in it may be revoked."""
    chain = list(dict.fromkeys(claims.chain))
    try:
        dlg = [uuid.UUID(d) for d in claims.delegation_ids]
    except ValueError as exc:
        raise TokenError("invalid token: malformed delegation id") from exc
    row = await conn.fetchrow(
        """
        SELECT
          (SELECT count(*) FROM agents WHERE id = ANY($1::text[])) AS known,
          (SELECT array_agg(id ORDER BY id) FROM agents WHERE id = ANY($1::text[]) AND status <> 'active') AS disabled,
          EXISTS (
            SELECT 1 FROM revocations
            WHERE jti = $2::uuid
               OR (agent_id = ANY($1::text[]) AND revoked_at >= $3)
          ) AS revoked,
          EXISTS (SELECT 1 FROM delegations WHERE id = ANY($4::uuid[]) AND revoked_at IS NOT NULL) AS dlg_revoked
        """,
        chain,
        claims.jti,
        datetime.fromtimestamp(claims.issued_at, tz=timezone.utc),
        dlg,
    )
    if row["known"] != len(chain):
        raise TokenError("unknown agent")
    if row["disabled"]:
        if not claims.delegated or claims.agent_id in row["disabled"]:
            raise TokenError("agent disabled by kill switch")
        raise TokenError(f"agent '{row['disabled'][0]}' in the delegation chain is disabled (kill switch)")
    if row["revoked"]:
        raise TokenError("token revoked")
    if row["dlg_revoked"]:
        raise TokenError("delegation revoked")
