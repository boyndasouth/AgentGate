"""Settings, read from environment variables (docker compose passes .env through).

No secrets live in code: every key below must come from the environment.
Generate them once with:  docker compose run --rm broker python -m app.keys
"""

from __future__ import annotations

import os
from dataclasses import dataclass


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
    )
