"""Settings, read from environment variables (docker compose passes .env through).

No secrets live in code: every key below must come from the environment.
Generate them once with:  docker compose run --rm broker python -m app.keys
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(
            f"Missing env var {name}. Generate secrets with "
            "`docker compose run --rm broker python -m app.keys` and add them to .env"
        )
    return value


@dataclass(frozen=True)
class Settings:
    database_url: str
    fga_api_url: str
    fga_store_id: str
    fga_model_id: str
    signing_key_b64: str      # Ed25519 private key seed (32 bytes, base64url)
    admin_api_key: str        # kill switch, revocation (Day 6: replaced by Auth0 login)
    orchestrator_api_key: str # only the orchestrator may mint agent tokens
    args_hmac_key: str        # keyed hash for tool args in the audit log
    token_ttl_seconds: int = 600
    issuer: str = "agentgate"
    audience: str = "agentgate-tools"
    # Day 4: approvals. A pending approval older than this expires, and expiry counts as deny.
    approval_ttl_seconds: int = 120
    # Slack (all optional). No bot token -> Slack off; approvals can still be decided via the admin API.
    #   SLACK_APP_TOKEN set (xapp-...)  -> Socket Mode: outbound websocket, no public URL (local dev)
    #   otherwise SLACK_SIGNING_SECRET -> HTTP mode: Slack POSTs clicks to /slack/events (Render)
    slack_bot_token: str = ""
    slack_signing_secret: str = ""
    slack_app_token: str = ""
    slack_channel: str = ""                     # channel ID (C0...), bot must be invited
    slack_approvers: dict[str, str] = field(default_factory=dict)   # Slack user ID -> AgentGate user

    @property
    def slack_mode(self) -> str:
        if not self.slack_bot_token:
            return "off"
        return "socket" if self.slack_app_token else "http"


def load_settings() -> Settings:
    return Settings(
        database_url=_required("DATABASE_URL"),
        fga_api_url=os.environ.get("FGA_API_URL", "http://openfga:8080").rstrip("/"),
        fga_store_id=_required("FGA_STORE_ID"),
        fga_model_id=_required("FGA_MODEL_ID"),
        signing_key_b64=_required("AGENTGATE_SIGNING_KEY"),
        admin_api_key=_required("AGENTGATE_ADMIN_KEY"),
        orchestrator_api_key=_required("AGENTGATE_ORCHESTRATOR_KEY"),
        args_hmac_key=_required("AGENTGATE_ARGS_HMAC_KEY"),
        token_ttl_seconds=int(os.environ.get("TOKEN_TTL_SECONDS", "600")),
        approval_ttl_seconds=int(os.environ.get("APPROVAL_TTL_SECONDS", "120")),
        **_slack_settings(),
    )


def _parse_approvers(raw: str) -> dict[str, str]:
    """SLACK_APPROVERS="U07ABC123=shiwin,U07XYZ789=alex" -> {"U07ABC123": "shiwin", ...}.
    Mapping a Slack user here only identifies them; OpenFGA still decides whether
    user:<name> is an `approver` of the specific tool."""
    out: dict[str, str] = {}
    for part in filter(None, (p.strip() for p in raw.split(","))):
        slack_id, sep, user = part.partition("=")
        if not sep or not slack_id.strip() or not user.strip():
            raise RuntimeError(f"SLACK_APPROVERS entry {part!r} must look like U0123ABCD=shiwin")
        out[slack_id.strip()] = user.strip().removeprefix("user:")
    return out


def _slack_settings() -> dict:
    env = {k: os.environ.get(k, "").strip() for k in (
        "SLACK_BOT_TOKEN", "SLACK_SIGNING_SECRET", "SLACK_APP_TOKEN", "SLACK_APPROVALS_CHANNEL", "SLACK_APPROVERS")}
    if env["SLACK_BOT_TOKEN"]:
        missing = [k for k in ("SLACK_APPROVALS_CHANNEL", "SLACK_APPROVERS") if not env[k]]
        if not env["SLACK_APP_TOKEN"] and not env["SLACK_SIGNING_SECRET"]:
            missing.append("SLACK_APP_TOKEN (Socket Mode) or SLACK_SIGNING_SECRET (HTTP mode)")
        if missing:
            raise RuntimeError(f"SLACK_BOT_TOKEN is set but missing: {', '.join(missing)}")
    return dict(
        slack_bot_token=env["SLACK_BOT_TOKEN"],
        slack_signing_secret=env["SLACK_SIGNING_SECRET"],
        slack_app_token=env["SLACK_APP_TOKEN"],
        slack_channel=env["SLACK_APPROVALS_CHANNEL"],
        slack_approvers=_parse_approvers(env["SLACK_APPROVERS"]),
    )
