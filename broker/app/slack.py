"""Slack approvals with Bolt for Python (Day 4).

Bolt in one paragraph: an `AsyncApp` holds the bot token and routes incoming Slack
payloads to listener functions you register with decorators. `@app.action(id)` fires
when someone clicks a button whose `action_id` matches. Every listener must call
`await ack()` within 3 seconds or Slack shows the user an error; Bolt sends the ack
first and lets the rest of the listener finish afterwards. `app.client` is an
`AsyncWebClient` for the Web API (chat.postMessage, chat.update, ...).

Two ways for clicks to reach us:
- Socket Mode (SLACK_APP_TOKEN=xapp-...): the broker opens an outbound websocket to
  Slack. No public URL, so it works on localhost. Used for local dev.
- HTTP mode (SLACK_SIGNING_SECRET): Slack POSTs to https://<broker>/slack/events and
  Bolt verifies the request signature. Used on Render.
Use one Slack app per mode (dev + prod); one app can't be in both at once.

Security notes:
- Agent-supplied values (args, reasons) are rendered as `plain_text`, so a prompt-injected
  email body can't @channel, link, or format its way into looking trustworthy.
- A click only identifies a Slack user. SLACK_APPROVERS maps that to an AgentGate user,
  and OpenFGA decides if that user is an `approver` of the tool (see approvals.py).
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Awaitable, Callable

from slack_bolt.adapter.asgi.async_handler import AsyncSlackRequestHandler
from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler
from slack_bolt.async_app import AsyncApp
from slack_sdk.web.async_client import AsyncWebClient

from .approvals import Approver, ApprovalError, summarize_args
from .config import Settings

log = logging.getLogger("agentgate.slack")

ACTION_APPROVE = "agentgate_approve"
ACTION_DENY = "agentgate_deny"
SLACK_EVENTS_PATH = "/slack/events"

Decide = Callable[..., Awaitable[dict]]   # ApprovalService.decide


def _plain(text: str) -> dict:
    return {"type": "plain_text", "text": (text or " ")[:1900], "emoji": False}


def _status_line(row: dict) -> str:
    status = row["status"]
    if status == "approved":
        result = row.get("result") or {}
        done = f"tool failed: {result['error']}" if "error" in result else f"tool ran: {result.get('status', 'ok')}"
        return f"✅ Approved by {row['approver']} · {done}"
    if status == "denied":
        return f"❌ Denied by {row['approver']}"
    if status == "expired":
        who = "agent stopped waiting" if row.get("resolved_via") == "agent-cancel" else "no decision in time"
        return f"⌛ Expired ({who}) · counted as deny"
    return "⏳ Waiting for a decision"


def approval_blocks(row: dict, *, args: dict | None = None) -> list[dict]:
    """Block Kit message for one approval. Buttons only while pending."""
    expires = int(row["expires_at"].timestamp())
    tainted = row.get("session_tainted")
    fields = [
        _plain(f"Agent: {row['agent_id']}"),
        _plain(f"Tool: {row['tool']}"),
        _plain(f"Session: {'⚠️ TAINTED (read untrusted content)' if tainted else 'clean'}"),
        _plain(f"Approval: {str(row['id'])[:8]}"),
    ]
    summary = summarize_args(row["tool"], args if args is not None else row.get("args"))
    args_text = "\n".join(f"{k}: {v}" for k, v in summary) or "(arguments cleared after decision)"
    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": f"Approval needed: {row['tool']}"}},
        {"type": "section", "fields": fields},
        {"type": "section", "text": _plain(f"Why: {row['reason']}")},
        {"type": "section", "text": _plain(args_text)},
        {"type": "context", "elements": [{
            "type": "mrkdwn",
            "text": (f"expires <!date^{expires}^{{time_secs}}|{row['expires_at']:%H:%M:%S} UTC> · "
                     f"audit #{row.get('audit_id', '—')} · id `{row['id']}`"),
        }]},
    ]
    if row["status"] == "pending":
        blocks.append({"type": "actions", "block_id": "agentgate_decision", "elements": [
            {"type": "button", "action_id": ACTION_APPROVE, "style": "primary", "value": str(row["id"]),
             "text": {"type": "plain_text", "text": "Approve"},
             "confirm": {
                 "title": {"type": "plain_text", "text": "Approve this call?"},
                 "text": _plain(f"{row['agent_id']} will run {row['tool']} with the arguments shown."),
                 "confirm": {"type": "plain_text", "text": "Approve"},
                 "deny": {"type": "plain_text", "text": "Cancel"}}},
            {"type": "button", "action_id": ACTION_DENY, "style": "danger", "value": str(row["id"]),
             "text": {"type": "plain_text", "text": "Deny"}},
        ]})
    else:
        blocks.append({"type": "section", "text": _plain(_status_line(row))})
    return blocks


def _fallback_text(row: dict) -> str:
    # Notification text; built only from our own identifiers, never agent-supplied values.
    if row["status"] == "pending":
        return f"Approval needed: {row['agent_id']} wants to run {row['tool']}"
    return f"{row['agent_id']} → {row['tool']}: {row['status']}"


class SlackApprovals:
    """Posts approval requests and turns button clicks into ApprovalService.decide calls."""

    def __init__(self, settings: Settings, decide: Decide, *, client: AsyncWebClient | None = None) -> None:
        self.settings = settings
        self.channel = settings.slack_channel
        self._decide = decide
        if client is not None:          # tests: a client pointed at a fake Slack
            self.app = AsyncApp(client=client, signing_secret=settings.slack_signing_secret or None)
        else:
            self.app = AsyncApp(token=settings.slack_bot_token,
                                signing_secret=settings.slack_signing_secret or None)
        self.http_handler = AsyncSlackRequestHandler(self.app, path=SLACK_EVENTS_PATH)
        self._socket: AsyncSocketModeHandler | None = None
        self.app.action(re.compile(f"^({ACTION_APPROVE}|{ACTION_DENY})$"))(self._on_click)

    # ---------------------------------------------------------------- lifecycle

    async def start(self) -> None:
        if self.settings.slack_mode == "socket":
            self._socket = AsyncSocketModeHandler(self.app, self.settings.slack_app_token)
            await self._socket.connect_async()
            log.info("Slack approvals: Socket Mode connected, channel %s", self.channel)
        else:
            log.info("Slack approvals: HTTP mode, Request URL must be https://<broker>%s", SLACK_EVENTS_PATH)

    async def stop(self) -> None:
        if self._socket is not None:
            await self._socket.close_async()

    # ---------------------------------------------------------------- outbound

    async def post(self, row: dict) -> tuple[str, str] | None:
        resp = await self.app.client.chat_postMessage(
            channel=self.channel, text=_fallback_text(row), blocks=approval_blocks(row), unfurl_links=False)
        return resp["channel"], resp["ts"]

    async def update(self, row: dict) -> None:
        await self.app.client.chat_update(
            channel=row["slack_channel"], ts=row["slack_ts"], text=_fallback_text(row),
            blocks=approval_blocks(row))

    # ---------------------------------------------------------------- inbound

    async def _on_click(self, ack: Callable, body: dict[str, Any], action: dict[str, Any],
                        client: AsyncWebClient) -> None:
        await ack()     # within 3 s, before any DB or policy work
        slack_user = body["user"]["id"]
        channel = (body.get("channel") or {}).get("id", self.channel)
        approve = action["action_id"] == ACTION_APPROVE

        async def tell(text: str) -> None:
            try:
                await client.chat_postEphemeral(channel=channel, user=slack_user, text=text)
            except Exception:   # noqa: BLE001
                log.exception("ephemeral reply failed")

        user = self.settings.slack_approvers.get(slack_user)
        if user is None:
            await tell(f"You ({slack_user}) aren't mapped to an AgentGate user, so you can't decide approvals. "
                       "Ask an admin to add you to SLACK_APPROVERS.")
            return
        try:
            approval_id = uuid.UUID(action["value"])
        except ValueError:
            await tell("That button carries an invalid approval id.")
            return
        try:
            row = await self._decide(approval_id, approve=approve,
                                     approver=Approver(user=user, via=f"slack:{slack_user}"))
        except ApprovalError as exc:
            await tell(f"Not applied: {exc}")
            return
        except Exception:   # noqa: BLE001
            log.exception("approval decision failed")
            await tell("AgentGate hit an error applying that decision; it is still pending.")
            return
        log.info("approval %s %s by %s", row["id"], row["status"], row["approver"])
