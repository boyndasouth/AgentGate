"""Ed25519 signing key, JWKS, and a secret generator.

Run `python -m app.keys` to print fresh secrets for .env.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SigningKey:
    """Holds the broker's Ed25519 key pair and its public JWK."""

    def __init__(self, seed_b64: str) -> None:
        seed = b64url_decode(seed_b64)
        if len(seed) != 32:
            raise RuntimeError("AGENTGATE_SIGNING_KEY must be a 32-byte Ed25519 seed (base64url)")
        self.private_key: Ed25519PrivateKey = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key: Ed25519PublicKey = self.private_key.public_key()
        raw_pub = self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw_pub)}
        # RFC 7638 thumbprint as the key id, so rotating keys changes the kid.
        canonical = json.dumps(self.public_jwk, separators=(",", ":"), sort_keys=True)
        self.kid = b64url(hashlib.sha256(canonical.encode()).digest())[:16]

    def jwks(self) -> dict:
        return {"keys": [{**self.public_jwk, "kid": self.kid, "alg": "EdDSA", "use": "sig"}]}


def generate_secrets() -> dict[str, str]:
    seed = Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return {
        "AGENTGATE_SIGNING_KEY": b64url(seed),
        "AGENTGATE_ADMIN_KEY": secrets.token_urlsafe(32),
        "AGENTGATE_ORCHESTRATOR_KEY": secrets.token_urlsafe(32),
        "AGENTGATE_ARGS_HMAC_KEY": secrets.token_urlsafe(32),
    }


if __name__ == "__main__":
    print("# --- AgentGate broker secrets: paste into .env (never commit) ---")
    for name, value in generate_secrets().items():
        print(f"{name}={value}")
