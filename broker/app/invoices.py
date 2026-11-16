"""Day 10 (closes G05): invoice matching, a mock of the accounts-payable system.

An allowlist bounds WHERE money goes, not WHETHER it is owed: a fake "$90 onboarding fee" to an
approved vendor got through (G05). So finance may pay a small amount alone only when the payment
matches an OPEN invoice from that payee for exactly that amount, and paying it marks it paid,
so the same invoice can't be paid twice without a human.

The broker computes `invoice_matches` and hands it to OpenFGA as context; the rule itself
(amount limit AND clean session AND known payee AND matching invoice) stays in the policy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

import asyncpg

INVOICE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


@dataclass(frozen=True)
class Match:
    ok: bool
    why: str | None = None      # why it doesn't match, for the escalation reason


def _money(amount: float) -> Decimal | None:
    """The amount exactly as sent: 40, 40.0 and 40.00 match an invoice of 40.00; 40.001 does not."""
    try:
        return Decimal(repr(float(amount)))
    except (InvalidOperation, ValueError, OverflowError):
        return None


async def match(conn: asyncpg.Connection, invoice_id: str, payee: str, amount: float) -> Match:
    if not invoice_id:
        return Match(False, "no invoice_id given")
    if not INVOICE_ID.fullmatch(invoice_id):
        return Match(False, "invoice_id is not a plain invoice number")
    row = await conn.fetchrow("SELECT payee, amount, status FROM invoices WHERE id = $1", invoice_id)
    if row is None:
        return Match(False, f"invoice {invoice_id} does not exist")
    if row["status"] != "open":
        return Match(False, f"invoice {invoice_id} is already paid")
    if row["payee"] != payee or _money(amount) != row["amount"]:
        return Match(False, f"invoice {invoice_id} is for a different payee or amount")
    return Match(True)


async def settle(conn: asyncpg.Connection, invoice_id: str, payee: str, amount: float) -> bool:
    """Mark the invoice paid, only if it is still open and still matches. One statement, so two
    concurrent payments of the same invoice can't both settle it. Call it in the same transaction
    as the payment, BEFORE paying: if the payment fails, the invoice reopens."""
    if not invoice_id:
        return False
    money = _money(amount)
    if money is None:
        return False
    row = await conn.fetchrow(
        """UPDATE invoices SET status = 'paid', paid_at = now()
           WHERE id = $1 AND status = 'open' AND payee = $2 AND amount = $3 RETURNING id""",
        invoice_id, payee, money)
    return row is not None


async def record_tx(conn: asyncpg.Connection, invoice_id: str, tx_id: str) -> None:
    await conn.execute("UPDATE invoices SET paid_tx = $2 WHERE id = $1", invoice_id, tx_id)


async def create(conn: asyncpg.Connection, invoice_id: str, payee: str, amount: float, created_by: str) -> dict:
    money = _money(amount)
    if money is None or money <= 0 or money != money.quantize(Decimal("0.01")):
        raise ValueError("amount must be positive with at most 2 decimals")
    if not INVOICE_ID.fullmatch(invoice_id):
        raise ValueError("id must be 1-64 letters, digits, '.', '_' or '-'")
    if not payee or len(payee) > 128 or any(ord(c) < 32 for c in payee):
        raise ValueError("payee must be 1-128 printable characters")
    row = await conn.fetchrow(
        """INSERT INTO invoices (id, payee, amount, created_by) VALUES ($1, $2, $3, $4)
           ON CONFLICT (id) DO NOTHING RETURNING id, payee, amount, status, created_at""",
        invoice_id, payee, money, created_by)
    if row is None:
        raise KeyError(f"invoice {invoice_id} already exists")
    return {**dict(row), "amount": float(row["amount"]), "created_at": row["created_at"].isoformat()}


async def listing(conn: asyncpg.Connection, limit: int = 50) -> list[dict]:
    rows = await conn.fetch(
        "SELECT id, payee, amount, status, created_at, paid_at FROM invoices ORDER BY created_at DESC LIMIT $1",
        max(1, min(limit, 500)))
    return [{**dict(r), "amount": float(r["amount"]), "created_at": r["created_at"].isoformat(),
             "paid_at": r["paid_at"].isoformat() if r["paid_at"] else None} for r in rows]
