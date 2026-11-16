"""Hash-chained, append-only audit log.

Each row's hash = sha256(prev_hash + canonical_json(row fields)).
Editing any field breaks that row's hash; deleting or reordering a row breaks
the next row's prev_hash link. GET /audit/verify recomputes the whole chain.

Someone with DB write access could rewrite the entire chain and recompute every hash, and
verify_chain would still pass. So the head is also published OUTSIDE the database (Day 8):
`checkpoint()` returns the latest (id, hash), signed with the broker's Ed25519 key, and a
scheduled GitHub Action appends it to a git branch (scripts/anchor.py). A rewrite then has to
change a hash that is already written down somewhere the database owner can't edit.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

import asyncpg

GENESIS_HASH = "0" * 64
_CHAIN_LOCK_ID = 7_412_001  # any constant; serializes appends across workers

# Fields covered by the hash, in a fixed order. Never reorder or rename.
HASHED_FIELDS = (
    "id", "ts", "event_type", "agent_id", "session_id", "task_id", "jti",
    "tool", "args_hash", "decision", "reason", "approver", "session_tainted",
)


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def args_digest(hmac_key: str, args: dict) -> str:
    """Keyed hash of tool arguments. Plain sha256 of small values (an amount, an
    address) can be brute-forced; HMAC with a server-side key can't."""
    return hmac.new(hmac_key.encode(), canonical_json(args).encode(), hashlib.sha256).hexdigest()


def utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def row_hash(prev_hash: str, fields: dict) -> str:
    payload = {k: fields.get(k) for k in HASHED_FIELDS}
    return hashlib.sha256((prev_hash + canonical_json(payload)).encode()).hexdigest()


async def append_event(
    conn: asyncpg.Connection,
    *,
    event_type: str,
    decision: str,
    reason: str,
    agent_id: str | None = None,
    session_id: str | None = None,
    task_id: str | None = None,
    jti: str | None = None,
    tool: str | None = None,
    args_hash: str | None = None,
    approver: str | None = None,
    session_tainted: bool | None = None,
) -> dict:
    """Append one event. Runs in its own transaction holding an advisory lock,
    so two concurrent requests can't both link to the same prev_hash."""
    async with conn.transaction():
        await conn.execute("SELECT pg_advisory_xact_lock($1)", _CHAIN_LOCK_ID)
        last = await conn.fetchrow("SELECT id, hash FROM audit_events ORDER BY id DESC LIMIT 1")
        prev_hash = last["hash"] if last else GENESIS_HASH
        fields = {
            "id": (last["id"] + 1) if last else 1,
            "ts": utc_ts(),
            "event_type": event_type,
            "agent_id": agent_id,
            "session_id": session_id,
            "task_id": task_id,
            "jti": jti,
            "tool": tool,
            "args_hash": args_hash,
            "decision": decision,
            "reason": reason,
            "approver": approver,
            "session_tainted": session_tainted,
        }
        digest = row_hash(prev_hash, fields)
        await conn.execute(
            """
            INSERT INTO audit_events (id, ts, event_type, agent_id, session_id, task_id, jti,
                tool, args_hash, decision, reason, approver, session_tainted, prev_hash, hash)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
            """,
            *(fields[k] for k in HASHED_FIELDS), prev_hash, digest,
        )
    return {**fields, "prev_hash": prev_hash, "hash": digest}


async def verify_chain(conn: asyncpg.Connection) -> dict:
    """Recompute every hash in order. Returns the first broken row, if any."""
    expected_prev = GENESIS_HASH
    expected_id = 1
    checked = 0
    async with conn.transaction():
        async for row in conn.cursor("SELECT * FROM audit_events ORDER BY id"):
            fields = dict(row)
            problem = None
            if fields["id"] != expected_id:
                problem = f"missing row(s): expected id {expected_id}, found {fields['id']}"
            elif fields["prev_hash"] != expected_prev:
                problem = "prev_hash does not match the previous row's hash (row deleted, inserted or reordered)"
            elif row_hash(fields["prev_hash"], fields) != fields["hash"]:
                problem = "hash mismatch: this row's contents were modified"
            if problem:
                return {
                    "valid": False,
                    "checked": checked,
                    "first_broken_id": fields["id"],
                    "problem": problem,
                }
            expected_prev = fields["hash"]
            expected_id += 1
            checked += 1
    return {"valid": True, "checked": checked, "head_hash": expected_prev}


# ---------------------------------------------------------------- anchoring (Day 8)

CHECKPOINT_TYP = "agentgate-audit-checkpoint+jwt"


async def head(conn: asyncpg.Connection) -> tuple[int, str]:
    """(last id, its hash); (0, GENESIS_HASH) for an empty log. Reads one row, no recompute."""
    last = await conn.fetchrow("SELECT id, hash FROM audit_events ORDER BY id DESC LIMIT 1")
    return (last["id"], last["hash"]) if last else (0, GENESIS_HASH)


async def checkpoint(conn: asyncpg.Connection, key: Any, issuer: str) -> dict:
    """The chain head as a signed statement: "at `iat`, row `last_id` had hash `head_hash`".
    A compact EdDSA JWS, verifiable with /.well-known/jwks.json. It has no `aud` and its own
    `typ`, so it can never be accepted as an agent token."""
    import jwt   # PyJWT; imported here so the hashing helpers above stay stdlib-only

    last_id, head_hash = await head(conn)
    claims = {"iss": issuer, "iat": int(datetime.now(timezone.utc).timestamp()),
              "last_id": last_id, "head_hash": head_hash}
    jws = jwt.encode(claims, key.private_key, algorithm="EdDSA",
                     headers={"kid": key.kid, "typ": CHECKPOINT_TYP})
    return {**claims, "kid": key.kid, "jws": jws}


async def hashes_at(conn: asyncpg.Connection, ids: list[int]) -> dict[str, str]:
    """Stored hash of each requested row (missing ids are left out). Used to compare the
    chain with anchors published earlier."""
    rows = await conn.fetch("SELECT id, hash FROM audit_events WHERE id = ANY($1::bigint[])", ids)
    return {str(r["id"]): r["hash"] for r in rows}
