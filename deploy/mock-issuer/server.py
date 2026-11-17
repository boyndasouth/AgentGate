"""Day 13: a stand-in for Auth0, for local tests only. Never deployed.

It speaks just enough of Auth0's machine-to-machine flow for the broker's agent login:

  GET  /.well-known/jwks.json   the RSA public key (new key, new kid, at every start)
  POST /oauth/token             client credentials grant (JSON or form body):
                                {grant_type, client_id, client_secret, audience} -> {access_token, ...}
                                Tokens look like Auth0's: RS256, iss, sub "<client_id>@clients",
                                aud, iat, exp, azp, gty "client-credentials".
  POST /sign                    TEST HOOK: {"claims": {...}, "key": "published" | "unpublished",
                                "kid": "..."} signs any claims, so tests can make expired tokens,
                                another audience, a user token, or one signed with a key that is
                                not in the JWKS.
  GET  /stats                   how many tokens /oauth/token has issued (the quota tests watch it)

Runs in the broker's image (it needs PyJWT and cryptography):
  python deploy/mock-issuer/server.py 9191
Env: MOCK_ISSUER_URL (the `iss` it writes, default http://mock-issuer:9191/),
     MOCK_ISSUER_CLIENTS ("id:secret,id2:secret2"), MOCK_ISSUER_TTL (seconds, default 86400).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = os.environ.get("MOCK_ISSUER_URL", "http://mock-issuer:9191/")
TTL = int(os.environ.get("MOCK_ISSUER_TTL", "86400"))
# Two ready-made M2M applications. The ids look like Auth0's (32 letters and digits).
DEFAULT_CLIENTS = ("mockClient0000000000000000000001:mock-secret-one,"
                   "mockClient0000000000000000000002:mock-secret-two,"
                   "mockClient0000000000000000000003:mock-secret-three")
CLIENTS = dict(pair.split(":", 1) for pair in os.environ.get("MOCK_ISSUER_CLIENTS", DEFAULT_CLIENTS).split(",") if ":" in pair)


def _b64(n: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()


def _make_key() -> tuple[rsa.RSAPrivateKey, dict]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key().public_numbers()
    jwk = {"kty": "RSA", "n": _b64(pub.n), "e": _b64(pub.e)}
    canonical = json.dumps(jwk, separators=(",", ":"), sort_keys=True)
    kid = base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()[:21]
    return key, {**jwk, "kid": kid, "use": "sig", "alg": "RS256"}


PUBLISHED, PUBLISHED_JWK = _make_key()
UNPUBLISHED, UNPUBLISHED_JWK = _make_key()     # a real RSA key that is NOT in the JWKS
ISSUED = 0


def _token(claims: dict, key: rsa.RSAPrivateKey, kid: str) -> str:
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        pass

    def _send(self, status: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(length, 65536)) if length else b""
        if "json" in (self.headers.get("Content-Type") or ""):
            try:
                data = json.loads(raw or b"{}")
            except ValueError:
                return {}
            return data if isinstance(data, dict) else {}
        return {k: v[0] for k, v in parse_qs(raw.decode(errors="replace")).items()}

    def do_GET(self) -> None:   # noqa: N802
        if self.path == "/.well-known/jwks.json":
            return self._send(200, {"keys": [PUBLISHED_JWK]})
        if self.path == "/stats":
            return self._send(200, {"tokens_issued": ISSUED, "issuer": ISSUER, "kid": PUBLISHED_JWK["kid"]})
        if self.path == "/health":
            return self._send(200, {"status": "ok"})
        self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:   # noqa: N802
        global ISSUED
        data = self._body()
        if self.path == "/oauth/token":
            client_id, secret = str(data.get("client_id", "")), str(data.get("client_secret", ""))
            if data.get("grant_type") != "client_credentials":
                return self._send(400, {"error": "unsupported_grant_type"})
            if not hmac.compare_digest(CLIENTS.get(client_id, "\0").encode(), secret.encode()):
                return self._send(401, {"error": "access_denied", "error_description": "Unauthorized"})
            if not data.get("audience"):
                return self._send(403, {"error": "access_denied", "error_description": "No audience parameter was provided"})
            now = int(time.time())
            ISSUED += 1
            claims = {"iss": ISSUER, "sub": f"{client_id}@clients", "aud": data["audience"], "iat": now,
                      "exp": now + TTL, "gty": "client-credentials", "azp": client_id}
            return self._send(200, {"access_token": _token(claims, PUBLISHED, PUBLISHED_JWK["kid"]),
                                    "token_type": "Bearer", "expires_in": TTL})
        if self.path == "/sign":
            claims = data.get("claims")
            if not isinstance(claims, dict):
                return self._send(400, {"error": "claims must be an object"})
            unpublished = data.get("key") == "unpublished"
            key = UNPUBLISHED if unpublished else PUBLISHED
            kid = str(data.get("kid") or (UNPUBLISHED_JWK if unpublished else PUBLISHED_JWK)["kid"])
            return self._send(200, {"token": _token(claims, key, kid)})
        self._send(404, {"error": "not_found"})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9191
    print(f"mock issuer on :{port}, iss={ISSUER}, {len(CLIENTS)} clients", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
