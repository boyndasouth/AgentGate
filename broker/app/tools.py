"""Five mock tools. They stand in for real Gmail / Stripe / CRM integrations.

Each tool has a typed argument struct (validated before the policy check) and a
`taints` flag: tools that return untrusted outside content. Day 5 uses that flag
to mark the session tainted.

Agents never see tool API keys. A real integration would read its key from the
broker's environment here, after the gate has allowed the call.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

import msgspec

# ---------- argument schemas ----------


class ReadWebArgs(msgspec.Struct, forbid_unknown_fields=True):
    url: str


class ReadInboxArgs(msgspec.Struct, forbid_unknown_fields=True):
    limit: int = 5


class SendEmailArgs(msgspec.Struct, forbid_unknown_fields=True):
    to: str
    subject: str
    body: str


class TransferFundsArgs(msgspec.Struct, forbid_unknown_fields=True):
    amount: float
    to_account: str
    memo: str = ""


class QueryCustomersArgs(msgspec.Struct, forbid_unknown_fields=True):
    limit: int = 10


# ---------- fake data ----------

_PAGES = {
    "https://example.com/pricing": "Acme Widgets pricing: Basic $10/mo, Pro $40/mo, Enterprise: contact sales.",
    "https://example.com/news": "Acme Widgets ships v2 with faster sync and an offline mode.",
    # TODO(Day 5): add the poisoned page with a hidden instruction to email the customer list outside.
}

_INBOX = [
    {"from": "vendor@supplies.example", "subject": "Invoice #1042", "body": "Amount due: $40.00"},
    {"from": "ceo@agentgate.example", "subject": "Q4 plan", "body": "Let's review on Monday."},
]

_CUSTOMERS = [
    {"id": i, "name": f"Customer {i}", "email": f"customer{i}@clients.example"} for i in range(1, 26)
]

OUTBOX: list[dict] = []     # sent mock emails, for inspection
LEDGER: list[dict] = []     # completed mock transfers

# ---------- implementations ----------


async def read_web(a: ReadWebArgs) -> dict:
    return {"url": a.url, "content": _PAGES.get(a.url, "404: page not found")}


async def read_inbox(a: ReadInboxArgs) -> dict:
    return {"messages": _INBOX[: max(0, a.limit)]}


async def send_email(a: SendEmailArgs) -> dict:
    msg = {"id": str(uuid.uuid4()), "to": a.to, "subject": a.subject}
    OUTBOX.append(msg)
    return {"status": "sent", **msg}


async def transfer_funds(a: TransferFundsArgs) -> dict:
    if a.amount <= 0:
        raise ValueError("amount must be positive")
    tx = {"tx_id": f"tx_{uuid.uuid4().hex[:12]}", "amount": a.amount, "to_account": a.to_account}
    LEDGER.append(tx)
    return {"status": "completed", **tx}


async def query_customers(a: QueryCustomersArgs) -> dict:
    return {"customers": _CUSTOMERS[: max(0, min(a.limit, len(_CUSTOMERS)))]}


# ---------- registry ----------


@dataclass(frozen=True)
class Tool:
    name: str
    args_type: type
    run: Callable[[Any], Awaitable[dict]]
    taints: bool = False                      # returns untrusted outside content
    amount_field: str | None = None           # arg sent to OpenFGA as `amount`


TOOLS: dict[str, Tool] = {
    t.name: t
    for t in (
        Tool("read_web", ReadWebArgs, read_web, taints=True),
        Tool("read_inbox", ReadInboxArgs, read_inbox, taints=True),
        Tool("send_email", SendEmailArgs, send_email),
        Tool("transfer_funds", TransferFundsArgs, transfer_funds, amount_field="amount"),
        Tool("query_customers", QueryCustomersArgs, query_customers),
    )
}


def parse_args(tool: Tool, raw: dict) -> Any:
    """Validate raw JSON args against the tool's schema. Raises msgspec.ValidationError."""
    return msgspec.convert(raw, tool.args_type)


def amount_of(tool: Tool, parsed: Any) -> float:
    return float(getattr(parsed, tool.amount_field)) if tool.amount_field else 0.0
