"""Prepare OpenFGA's Postgres store in Supabase, before `openfga migrate` (Day 10).

OpenFGA gets its own login role `openfga` and its own schema `openfga`:
  - the role's default search_path is the schema, set ON THE ROLE (server-side). Supabase's
    pooler (Supavisor) doesn't reliably pass a search_path from the connection string, so a
    URL parameter could silently put OpenFGA's tables in `public`, which Supabase serves through
    its REST API;
  - the role may only use and create tables in its schema (it owns those tables, not the schema)
    and is granted nothing in `public`, so OpenFGA can't read or write the broker's tables.

Run with DATABASE_URL (the broker's admin connection) and FGA_DB_PASSWORD (OpenFGA's own secret).
The password is sent as a SCRAM-SHA-256 verifier, never in plain text, so it can't end up in a
statement log. Prints `export OPENFGA_DATASTORE_URI=...` for start.sh: the same host, port,
database and sslmode as DATABASE_URL, with the openfga user (`openfga.<ref>` on the pooler).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import shlex
import sys
import urllib.parse

import asyncpg

ROLE = SCHEMA = "openfga"


def scram_verifier(password: str, iterations: int = 4096) -> str:
    """What Postgres stores for a SCRAM-SHA-256 password (RFC 5802 / RFC 7677)."""
    salt = os.urandom(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    stored_key = hashlib.sha256(hmac.new(salted, b"Client Key", "sha256").digest()).digest()
    server_key = hmac.new(salted, b"Server Key", "sha256").digest()
    b64 = lambda b: base64.b64encode(b).decode()
    return f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"


def fga_uri(database_url: str, password: str) -> str:
    u = urllib.parse.urlsplit(database_url)
    user = u.username or "postgres"
    # Supabase pooler user names are "<role>.<project ref>": keep the ref, swap the role.
    fga_user = ROLE + (user[user.index("."):] if "." in user else "")
    host = u.hostname or "localhost"
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{urllib.parse.quote(fga_user, safe='')}:{urllib.parse.quote(password, safe='')}@{host}"
    if u.port:
        netloc += f":{u.port}"
    q = {k: v for k, v in urllib.parse.parse_qsl(u.query) if k == "sslmode"}
    return urllib.parse.urlunsplit(("postgres", netloc, u.path or "/postgres", urllib.parse.urlencode(q), ""))


async def main() -> None:
    password = os.environ["FGA_DB_PASSWORD"]
    if len(password) < 16:
        sys.exit("[fga_db] FGA_DB_PASSWORD must be at least 16 characters")
    database_url = os.environ["DATABASE_URL"]
    conn = await asyncpg.connect(database_url, timeout=30)
    try:
        verifier = await conn.fetchval("SELECT quote_literal($1)", scram_verifier(password))
        exists = await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", ROLE)
        verb = "ALTER" if exists else "CREATE"
        await conn.execute(f"{verb} ROLE {ROLE} WITH LOGIN PASSWORD {verifier}")
        # The schema stays owned by the admin user; openfga gets USAGE + CREATE on it, so the tables
        # `openfga migrate` creates are owned by openfga. Making openfga the schema OWNER would need
        # SET ROLE openfga, which a non-superuser creator (Supabase's postgres, Postgres 16+) lacks.
        await conn.execute(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}")
        await conn.execute(f"GRANT USAGE, CREATE ON SCHEMA {SCHEMA} TO {ROLE}")
        await conn.execute(f"ALTER ROLE {ROLE} SET search_path = {SCHEMA}")
        db = await conn.fetchval("SELECT current_database()")
        await conn.execute(f'GRANT CONNECT ON DATABASE "{db}" TO {ROLE}')
        await conn.execute(f"REVOKE CREATE ON SCHEMA public FROM {ROLE}")
    finally:
        await conn.close()
    print(f"[fga_db] role {ROLE} ({'updated' if exists else 'created'}), schema {SCHEMA} ready", file=sys.stderr)
    print(f"export OPENFGA_DATASTORE_URI={shlex.quote(fga_uri(database_url, password))}")


if __name__ == "__main__":
    asyncio.run(main())
