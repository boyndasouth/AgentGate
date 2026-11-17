"""Day 13: agents log in as themselves (Auth0 machine-to-machine).

An external agent is an Auth0 M2M application. It gets an Auth0 access token with the client
credentials grant (audience = the AgentGate API) and trades it at POST /tokens/agent for the
usual short-lived AgentGate token. This module only answers one question: which Auth0 client
does this bearer token prove? Everything after that (which agent, which scopes, which session)
is decided in main.py from the broker's own tables and OpenFGA.

What is accepted:
  - alg RS256 only, signed by a key in the issuer's JWKS (fetched over https, cached). A token
    that says `none`, HS256 or anything else is refused before any key is looked at.
  - iss, aud, exp, iat (not older than AUTH0_MAX_TOKEN_AGE_SECONDS) and nbf.
  - a client-credentials token: gty = client-credentials, sub = "<client_id>@clients",
    azp = client_id. A user's access token for the same API is refused.

Two kinds of refusal, on purpose (same rule as agent tokens since Day 2):
  Forged    the signature can't be tied to the issuer (wrong alg, unknown key, bad signature,
            not a JWT). 401, logged, NOT written to the audit chain: anyone on the internet
            can send these, and junk must not be able to flood the chain.
  Rejected  signed by the issuer but not usable here (expired, another audience, a user
            token, too old). 401 and audited: the sender holds a real token from our tenant.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
import jwt

log = logging.getLogger("agentgate.login")

CLIENT_ID = re.compile(r"[A-Za-z0-9_-]{8,64}")       # Auth0 client ids are 32 letters and digits
MAX_TOKEN_CHARS = 8192
MAX_JWKS_BYTES = 64 * 1024
MAX_KEYS = 20
JWKS_TTL = 3600.0          # refetch the key set after an hour
JWKS_RETRY = 60.0          # an unknown kid (or a failed fetch) triggers at most one fetch per minute
CLOCK_SKEW = 60            # seconds an `iat` / `nbf` may lie in the future
EXP_LEEWAY = 5


class LoginError(Exception):
    def __init__(self, reason: str, client_id: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.client_id = client_id


class Forged(LoginError):
    """Not provably from the issuer -> 401, not audited."""


class Rejected(LoginError):
    """Signed by the issuer, but not a usable agent login -> 401, audited."""


class Unavailable(LoginError):
    """The issuer's keys can't be fetched -> 503 (fail closed)."""


@dataclass(frozen=True)
class LoginConfig:
    issuer: str            # exactly as it appears in `iss`, e.g. https://dev-abc.us.auth0.com/
    audience: str          # the AgentGate API identifier in Auth0
    jwks_url: str
    max_age: int = 86400   # Auth0's default lifetime for an API's access tokens


@dataclass(frozen=True)
class Login:
    client_id: str
    expires_at: int


def load_config(env: dict[str, str] | None = None) -> LoginConfig | None:
    """None = agent login is off (POST /tokens/agent answers 503). Raises RuntimeError on a
    half-configured or unsafe setup, so the broker refuses to boot instead of guessing.

      AUTH0_DOMAIN     dev-abc123.us.auth0.com   (issuer = https://<domain>/)
      AUTH0_AUDIENCE   the API identifier you created in Auth0, e.g. https://agentgate-broker.onrender.com
      AUTH0_MAX_TOKEN_AGE_SECONDS   optional, default 86400

    For the local mock issuer only (compose): AUTH0_ISSUER and AUTH0_JWKS_URL replace the
    domain, and AUTH0_INSECURE_HOSTS names the hosts whose JWKS may be fetched over plain http.
    """
    env = os.environ if env is None else env
    get = lambda k: (env.get(k) or "").strip()   # noqa: E731
    domain, audience = get("AUTH0_DOMAIN"), get("AUTH0_AUDIENCE")
    issuer, jwks_url = get("AUTH0_ISSUER"), get("AUTH0_JWKS_URL")
    if not (domain or audience or issuer or jwks_url):
        return None
    if not audience:
        raise RuntimeError("AUTH0_AUDIENCE is missing: set it to the identifier of the AgentGate API in Auth0")
    if domain:
        # People paste the tenant URL: accept https://dev-abc.us.auth0.com/ as well as the bare name.
        domain = domain.removeprefix("https://").rstrip("/")
        if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", domain) or "." not in domain:
            raise RuntimeError("AUTH0_DOMAIN must be the tenant's host name, like dev-abc123.us.auth0.com")
        issuer = issuer or f"https://{domain}/"
        jwks_url = jwks_url or f"https://{domain}/.well-known/jwks.json"
    if not issuer or not jwks_url:
        raise RuntimeError("set AUTH0_DOMAIN, or both AUTH0_ISSUER and AUTH0_JWKS_URL")
    parts = urlsplit(jwks_url)
    insecure = {h.strip().lower() for h in get("AUTH0_INSECURE_HOSTS").split(",") if h.strip()}
    if parts.scheme != "https" and not (parts.scheme == "http" and (parts.hostname or "").lower() in insecure):
        raise RuntimeError("AUTH0_JWKS_URL must be https (plain http only for hosts named in AUTH0_INSECURE_HOSTS)")
    if not parts.hostname or parts.username or parts.password:
        raise RuntimeError("AUTH0_JWKS_URL is not a plain URL")
    raw_age = get("AUTH0_MAX_TOKEN_AGE_SECONDS") or "86400"
    if not raw_age.isdigit() or not 60 <= int(raw_age) <= 30 * 86400:
        raise RuntimeError("AUTH0_MAX_TOKEN_AGE_SECONDS must be a number of seconds between 60 and 2592000")
    return LoginConfig(issuer=issuer, audience=audience, jwks_url=jwks_url, max_age=int(raw_age))


def _usable_keys(doc: object) -> dict[str, object]:
    """kid -> public key, for the RSA signing keys of a JWKS document. Anything else is skipped."""
    out: dict[str, object] = {}
    keys = doc.get("keys") if isinstance(doc, dict) else None
    if not isinstance(keys, list):
        raise ValueError("no keys")
    for jwk in keys[:MAX_KEYS]:
        if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
            continue
        if jwk.get("use") not in (None, "sig") or jwk.get("alg") not in (None, "RS256"):
            continue
        kid = jwk.get("kid")
        if not isinstance(kid, str) or not 0 < len(kid) <= 200:
            continue
        try:
            key = jwt.PyJWK({k: jwk[k] for k in ("kty", "n", "e") if k in jwk}, algorithm="RS256").key
        except (jwt.InvalidKeyError, jwt.PyJWKError, KeyError, ValueError, TypeError):
            continue
        if getattr(key, "key_size", 0) < 2048:
            continue
        out[kid] = key
    return out


class AgentLogin:
    """Verifies Auth0 access tokens against the issuer's JWKS. One per broker process."""

    def __init__(self, config: LoginConfig, client: httpx.AsyncClient | None = None) -> None:
        self.config = config
        # No proxy from the environment and no redirects: the keys come from the configured
        # URL or not at all.
        self._client = client or httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=5.0)
        self._keys: dict[str, object] = {}
        self._fetched_at = 0.0       # last successful fetch
        self._tried_at = 0.0         # last attempt, successful or not
        self._lock = asyncio.Lock()

    async def close(self) -> None:
        await self._client.aclose()

    async def _fetch(self) -> None:
        self._tried_at = time.monotonic()
        try:
            async with self._client.stream("GET", self.config.jwks_url, headers={"accept": "application/json"}) as resp:
                if resp.status_code != 200:
                    raise ValueError(f"HTTP {resp.status_code}")
                body = b""
                async for chunk in resp.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_JWKS_BYTES:
                        raise ValueError("key set too large")
            keys = _usable_keys(json.loads(body))
        except (httpx.HTTPError, ValueError) as exc:
            # Our own ValueErrors carry a short reason; anything else is named by type only.
            why = str(exc) if type(exc) is ValueError else type(exc).__name__
            log.warning("agent login: can't fetch the issuer's keys from %s: %s", self.config.jwks_url, why)
            return
        if keys:
            self._keys, self._fetched_at = keys, self._tried_at

    async def _key(self, kid: str) -> object | None:
        now = time.monotonic()
        fresh = self._keys and now - self._fetched_at < JWKS_TTL
        if fresh and kid in self._keys:
            return self._keys[kid]
        async with self._lock:
            now = time.monotonic()
            stale = not self._keys or now - self._fetched_at >= JWKS_TTL
            # A key we don't know may be a rotation, or junk: look again, but not more than once a minute.
            if (stale or kid not in self._keys) and (self._tried_at == 0.0 or now - self._tried_at >= JWKS_RETRY):
                await self._fetch()
        if not self._keys or time.monotonic() - self._fetched_at >= JWKS_TTL:
            # Never verify against keys that couldn't be refreshed for over an hour: a key the
            # issuer has withdrawn would stay trusted for as long as the fetch keeps failing.
            raise Unavailable("the identity provider's signing keys can't be fetched; failing closed")
        return self._keys.get(kid)

    async def verify(self, bearer: str, now: float | None = None) -> Login:
        cfg = self.config
        if not bearer or len(bearer) > MAX_TOKEN_CHARS or bearer.count(".") != 2:
            raise Forged("not a JWT")
        try:
            header = jwt.get_unverified_header(bearer)
        except jwt.InvalidTokenError as exc:
            raise Forged("not a JWT") from exc
        if header.get("alg") != "RS256":
            raise Forged("only RS256 tokens from the identity provider are accepted")
        kid = header.get("kid")
        if not isinstance(kid, str) or not 0 < len(kid) <= 200:
            raise Forged("token names no signing key")
        key = await self._key(kid)
        if key is None:
            raise Forged("token is signed with a key the identity provider doesn't publish")
        try:
            # Signature first, claims after: a refusal below is then known to concern a token
            # the issuer really signed, which is what makes it worth an audit row.
            claims = jwt.decode(bearer, key, algorithms=["RS256"],
                                options={"verify_signature": True, "verify_exp": False, "verify_nbf": False,
                                         "verify_iat": False, "verify_aud": False, "verify_iss": False,
                                         "verify_sub": False, "verify_jti": False})
        except (jwt.InvalidSignatureError, jwt.DecodeError, jwt.InvalidAlgorithmError, jwt.InvalidKeyError) as exc:
            raise Forged("bad signature") from exc
        except jwt.InvalidTokenError as exc:      # the signature held; PyJWT disliked a claim's shape
            raise Rejected("token has malformed claims") from exc

        sub, azp = claims.get("sub"), claims.get("azp")
        client_id = None
        if isinstance(sub, str) and sub.endswith("@clients") and CLIENT_ID.fullmatch(sub[: -len("@clients")]):
            client_id = sub[: -len("@clients")]

        def reject(reason: str) -> Rejected:
            return Rejected(reason, client_id)

        if claims.get("iss") != cfg.issuer:
            raise reject("token is from another issuer")
        aud = claims.get("aud")
        if not (aud == cfg.audience or (isinstance(aud, list) and cfg.audience in aud)):
            raise reject("token was issued for another audience, not for AgentGate")
        t = time.time() if now is None else now
        exp, iat, nbf = claims.get("exp"), claims.get("iat"), claims.get("nbf")
        if not _is_time(exp) or not _is_time(iat) or (nbf is not None and not _is_time(nbf)):
            raise reject("token has no usable exp / iat")
        if t > exp + EXP_LEEWAY:
            raise reject("token expired")
        if iat > t + CLOCK_SKEW or (nbf is not None and nbf > t + CLOCK_SKEW):
            raise reject("token is not valid yet")
        if t - iat > cfg.max_age:
            raise reject(f"token is older than {cfg.max_age} s; get a new one from the identity provider")
        if client_id is None or claims.get("gty") != "client-credentials" or azp != client_id:
            raise reject("not a machine-to-machine (client credentials) token")
        return Login(client_id=client_id, expires_at=int(exp))


def _is_time(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and 0 < value < 2**40


def bearer_of(header_value: str | None) -> str:
    scheme, _, token = (header_value or "").partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""
