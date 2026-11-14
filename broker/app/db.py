"""Postgres connection pool (asyncpg) and schema bootstrap."""

from __future__ import annotations

import json
from pathlib import Path

import asyncpg

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema.sql"


async def _init_conn(conn: asyncpg.Connection) -> None:
    # Let asyncpg send/receive jsonb as Python dicts.
    await conn.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")


async def create_pool(database_url: str) -> asyncpg.Pool:
    pool = await asyncpg.create_pool(database_url, min_size=1, max_size=10, init=_init_conn)
    async with pool.acquire() as conn:
        await conn.execute(SCHEMA_PATH.read_text())
    return pool
