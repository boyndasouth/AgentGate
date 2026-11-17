"""Day 13: agents log in as themselves (Auth0 machine-to-machine).

  unit   no broker, no database: the login settings, which JWKS keys are usable, token
         verification (alg swaps, signatures, every claim) and the key cache, against an
         in-process fake JWKS endpoint.
  live   against a running LOCAL broker, its database and the mock issuer
         (deploy/mock-issuer/server.py). Runs the Day 13 done check: a standalone script with
         only a client id and secret gets a token and calls a granted tool; wrong audience,
         expired token, alg swap and an unmapped client are refused; the kill switch kills the
         agent's live tokens. Also: sessions an agent may and may not join, taint that follows
         the agent into a new session, and the orchestrator key losing the agent.
         Registers d13-bot, d13-peer and d13-other; they stay registered (agents are disabled,
         never deleted) with no grants.

  .\\scripts\\test_day13.ps1              # both parts, in the broker's container
  .\\scripts\\test_day13.ps1 -UnitOnly
  python broker/tests/test_day13.py [--unit-only]
      env: DATABASE_URL, AGENTGATE_ADMIN_KEY, AGENTGATE_ORCHESTRATOR_KEY,
           AGENTGATE_URL (default http://broker:8000), MOCK_ISSUER_URL (default http://mock-issuer:9191),
           AUTH0_AUDIENCE (what the broker expects; default https://agentgate.local/api)

Never point it at production: it registers agents and changes grants. Exit 0 = all passed.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))     # broker/ (or /srv in the container)

import httpx  # noqa: E402
import jwt  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa  # noqa: E402

from app import agent_login  # noqa: E402
from app.agent_login import AgentLogin, Forged, LoginConfig, Rejected, Unavailable  # noqa: E402

FAILED: list[str] = []
COUNT = 0


def check(name: str, ok: bool, detail: object = "") -> None:
    global COUNT
    COUNT += 1
    if not ok:
        FAILED.append(name)
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + (f"   [{str(detail)[:300]}]" if detail and not ok else ""))


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64int(n: int) -> str:
    return b64(n.to_bytes((n.bit_length() + 7) // 8, "big"))


def jwk_of(key: rsa.RSAPrivateKey, kid: str, **extra) -> dict:
    pub = key.public_key().public_numbers()
    return {"kty": "RSA", "n": b64int(pub.n), "e": b64int(pub.e), "kid": kid, "use": "sig", "alg": "RS256", **extra}


def hs256_with_public_key(claims: dict, jwk: dict, kid: str) -> str:
    """The classic alg-confusion token: HS256, with the RSA PUBLIC key as the HMAC secret.
    PyJWT refuses to build one, so it is assembled by hand, in the PEM and the JWK flavour."""
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid}).encode())
    body = b64(json.dumps(claims).encode())
    secret = jwt.PyJWK({k: jwk[k] for k in ("kty", "n", "e")}, algorithm="RS256").key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    sig = hmac.new(secret, f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64(sig)}"


def unsigned(claims: dict, alg: str = "none", kid: str | None = None) -> str:
    header = {"alg": alg, "typ": "JWT", **({"kid": kid} if kid else {})}
    return f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims).encode())}."


ISS, AUD, CID = "https://tenant.example/", "https://agentgate.example/api", "unitClient000000000000000000001"


def good_claims(now: float, **over) -> dict:
    claims = {"iss": ISS, "sub": f"{CID}@clients", "aud": AUD, "iat": int(now) - 10, "exp": int(now) + 3600,
              "gty": "client-credentials", "azp": CID}
    claims.update(over)
    return {k: v for k, v in claims.items() if v is not None}


# ------------------------------------------------------------------ unit


class FakeIssuer:
    """An in-process JWKS endpoint (httpx.MockTransport) whose answers the tests can change."""

    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "unit-key-1"
        self.jwks: object = {"keys": [jwk_of(self.key, self.kid)]}
        self.status = 200
        self.fetches = 0
        self.raw: bytes | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.fetches += 1
        if self.status in (301, 302):
            return httpx.Response(self.status, headers={"location": "https://elsewhere.example/jwks.json"})
        if self.raw is not None:
            return httpx.Response(self.status, content=self.raw)
        return httpx.Response(self.status, json=self.jwks)

    def service(self, max_age: int = 86400) -> AgentLogin:
        cfg = LoginConfig(issuer=ISS, audience=AUD, jwks_url="https://tenant.example/.well-known/jwks.json",
                          max_age=max_age)
        return AgentLogin(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(self.handler)))

    def sign(self, claims: dict, kid: str | None = None, key=None, alg: str = "RS256") -> str:
        return jwt.encode(claims, key or self.key, algorithm=alg, headers={"kid": kid or self.kid})


async def outcome(svc: AgentLogin, token: str, now: float | None = None):
    try:
        return await svc.verify(token, now=now)
    except (Forged, Rejected, Unavailable) as exc:
        return exc


def config_problem(env: dict) -> str | None:
    try:
        agent_login.load_config(env)
    except RuntimeError as exc:
        return str(exc)
    return None


async def unit() -> None:
    print("unit: login settings")
    check("no AUTH0_* settings: agent login is off", agent_login.load_config({}) is None)
    cfg = agent_login.load_config({"AUTH0_DOMAIN": "dev-abc.us.auth0.com", "AUTH0_AUDIENCE": "https://ag/api"})
    check("a domain gives the issuer with a trailing slash", cfg.issuer == "https://dev-abc.us.auth0.com/", cfg)
    check("  ... and the https JWKS URL", cfg.jwks_url == "https://dev-abc.us.auth0.com/.well-known/jwks.json")
    check("  ... and a 24 h maximum token age", cfg.max_age == 86400)
    check("a domain without an audience stops the boot", "AUTH0_AUDIENCE" in (config_problem({"AUTH0_DOMAIN": "a.b.com"}) or ""))
    check("an audience without a domain stops the boot", config_problem({"AUTH0_AUDIENCE": "x"}) is not None)
    pasted = agent_login.load_config({"AUTH0_DOMAIN": "https://dev-abc.us.auth0.com/", "AUTH0_AUDIENCE": "x"})
    check("a domain pasted as a URL is read as the host name", pasted.issuer == "https://dev-abc.us.auth0.com/"
          and pasted.jwks_url == "https://dev-abc.us.auth0.com/.well-known/jwks.json", pasted)
    for bad in ("http://dev-abc.us.auth0.com", "dev-abc.us.auth0.com/path", "localhost", "a b.com", "user@dev-abc.us.auth0.com"):
        check(f"AUTH0_DOMAIN={bad} is refused", config_problem({"AUTH0_DOMAIN": bad, "AUTH0_AUDIENCE": "x"}) is not None)
    mock = {"AUTH0_ISSUER": "http://mock-issuer:9191/", "AUTH0_JWKS_URL": "http://mock-issuer:9191/.well-known/jwks.json",
            "AUTH0_AUDIENCE": "x"}
    check("a plain-http JWKS URL is refused", "https" in (config_problem(mock) or ""))
    check("  ... unless its host is named in AUTH0_INSECURE_HOSTS",
          config_problem({**mock, "AUTH0_INSECURE_HOSTS": "mock-issuer"}) is None)
    check("  ... and only that host", config_problem({**mock, "AUTH0_INSECURE_HOSTS": "other-host"}) is not None)
    check("a JWKS URL with credentials in it is refused", config_problem(
        {"AUTH0_ISSUER": "https://a.example/", "AUTH0_JWKS_URL": "https://u:p@a.example/jwks", "AUTH0_AUDIENCE": "x"}) is not None)
    for bad in ("0", "abc", "-5", "99999999"):
        check(f"AUTH0_MAX_TOKEN_AGE_SECONDS={bad} is refused", config_problem(
            {"AUTH0_DOMAIN": "a.b.com", "AUTH0_AUDIENCE": "x", "AUTH0_MAX_TOKEN_AGE_SECONDS": bad}) is not None)

    print("unit: which JWKS keys are usable")
    big = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    usable = agent_login._usable_keys({"keys": [
        jwk_of(big, "ok"), jwk_of(big, "enc", use="enc"), jwk_of(big, "rs384", alg="RS384"), jwk_of(small, "small"),
        {"kty": "oct", "k": "c2VjcmV0", "kid": "oct"}, {"kty": "EC", "kid": "ec"}, {**jwk_of(big, "x"), "kid": 7},
        {"kty": "RSA", "kid": "broken", "n": "!!", "e": "AQAB"}, "junk",
        {k: v for k, v in jwk_of(big, "bare").items() if k not in ("use", "alg")}]})
    check("only RSA signing keys of 2048 bits or more are kept", set(usable) == {"ok", "bare"}, set(usable))
    for doc in ({}, {"keys": "x"}, [], "x"):
        try:
            agent_login._usable_keys(doc)
            check(f"a JWKS document like {doc!r} is refused", False)
        except ValueError:
            check(f"a JWKS document like {doc!r} is refused", True)

    print("unit: token verification")
    iss = FakeIssuer()
    svc = iss.service()
    now = time.time()
    res = await outcome(svc, iss.sign(good_claims(now)))
    check("a well-formed client-credentials token is accepted", getattr(res, "client_id", None) == CID, res)
    res = await outcome(svc, iss.sign(good_claims(now, aud=["https://other/api", AUD])))
    check("an audience list that contains AgentGate is accepted", getattr(res, "client_id", None) == CID, res)

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ed = ed25519.Ed25519PrivateKey.generate()
    signed = iss.sign(good_claims(now))
    head, body, sig = signed.split(".")
    tampered = f"{head}.{b64(json.dumps(good_claims(now, sub='otherClient0000000000000000000001@clients', azp='otherClient0000000000000000000001')).encode())}.{sig}"
    forged = {
        "alg none": unsigned(good_claims(now), "none", iss.kid),
        "alg None (capital)": unsigned(good_claims(now), "None", iss.kid),
        "alg none with the real signature attached": f"{b64(json.dumps({'alg': 'none', 'kid': iss.kid}).encode())}.{body}.{sig}",
        "HS256 keyed with the public key (alg confusion)": hs256_with_public_key(good_claims(now), jwk_of(iss.key, iss.kid), iss.kid),
        "HS256 with a guessed secret": jwt.encode(good_claims(now), "secret-secret-secret-secret-secret-1", algorithm="HS256", headers={"kid": iss.kid}),
        "RS384 from the right key": iss.sign(good_claims(now), alg="RS384"),
        "PS256 from the right key": iss.sign(good_claims(now), alg="PS256"),
        "EdDSA": jwt.encode(good_claims(now), ed, algorithm="EdDSA", headers={"kid": iss.kid}),
        "RS256 from another key, claiming the published kid": iss.sign(good_claims(now), key=other),
        "RS256 from another key with its own kid": iss.sign(good_claims(now), key=other, kid="attacker-key"),
        "a payload changed after signing": tampered,
        "no kid": jwt.encode(good_claims(now), iss.key, algorithm="RS256"),
        "an empty kid": jwt.encode(good_claims(now), iss.key, algorithm="RS256", headers={"kid": ""}),
        "an embedded jwk header": jwt.encode(good_claims(now), other, algorithm="RS256",
                                             headers={"kid": iss.kid, "jwk": jwk_of(other, iss.kid)}),
        "a jku header pointing elsewhere": jwt.encode(good_claims(now), other, algorithm="RS256",
                                                      headers={"kid": iss.kid, "jku": "https://evil.example/jwks.json"}),
        "garbage": "not-a-token",
        "an empty string": "",
        "two segments": f"{head}.{body}",
        "an oversized token": iss.sign(good_claims(now, pad="x" * 9000)),
    }
    for name, token in forged.items():
        res = await outcome(svc, token)
        check(f"forged: {name} -> refused, not audit-worthy", isinstance(res, Forged), res)

    rejected = {
        "another issuer": good_claims(now, iss="https://evil.example/"),
        "the issuer without its trailing slash": good_claims(now, iss=ISS.rstrip("/")),
        "another audience": good_claims(now, aud="https://other/api"),
        "an audience list without AgentGate": good_claims(now, aud=["https://a", "https://b"]),
        "no audience": good_claims(now, aud=None),
        "expired": good_claims(now, iat=int(now) - 7200, exp=int(now) - 60),
        "no exp": good_claims(now, exp=None),
        "exp as a string": good_claims(now, exp=str(int(now) + 3600)),
        "exp true": good_claims(now, exp=True),
        "no iat": good_claims(now, iat=None),
        "issued in the future": good_claims(now, iat=int(now) + 600),
        "nbf in the future": good_claims(now, nbf=int(now) + 600),
        "older than the maximum age": good_claims(now, iat=int(now) - 90000, exp=int(now) + 3600),
        "a user's access token (sub auth0|...)": good_claims(now, sub="auth0|64f0c0ffee", gty=None, azp=CID),
        "a user's token with gty password": good_claims(now, sub="auth0|64f0c0ffee", gty="password"),
        "client-credentials without gty": good_claims(now, gty=None),
        "azp naming another client": good_claims(now, azp="otherClient0000000000000000000001"),
        "no azp": good_claims(now, azp=None),
        "sub without @clients": good_claims(now, sub=CID),
        "a client id with odd characters": good_claims(now, sub="bad client!@clients", azp="bad client!"),
        "sub as a number": good_claims(now, sub=12345),
    }
    for name, claims in rejected.items():
        res = await outcome(svc, iss.sign(claims))
        check(f"signed but unusable: {name} -> rejected", isinstance(res, Rejected), res)
    res = await outcome(svc, iss.sign(good_claims(now, aud="https://other/api")))
    check("a rejection names the client, so the audit row can", getattr(res, "client_id", None) == CID)
    check("  ... and never repeats the claim it disliked", "other/api" not in getattr(res, "reason", ""))
    res = await outcome(svc, iss.sign(good_claims(now, exp=int(now) - 3)))
    check("5 s of leeway on exp", getattr(res, "client_id", None) == CID, res)
    short = iss.service(max_age=600)
    res = await outcome(short, iss.sign(good_claims(now, iat=int(now) - 900)))
    check("AUTH0_MAX_TOKEN_AGE_SECONDS is enforced", isinstance(res, Rejected) and "older" in res.reason, res)
    check("bearer_of takes the token out of the header", agent_login.bearer_of("Bearer abc.def.ghi") == "abc.def.ghi")
    check("  ... and nothing from another scheme", agent_login.bearer_of("Basic abc") == "" and agent_login.bearer_of(None) == "")

    print("unit: the key cache")
    iss = FakeIssuer()
    svc = iss.service()
    clock = [1000.0]
    real_monotonic = agent_login.time.monotonic
    agent_login.time.monotonic = lambda: clock[0]
    try:
        for _ in range(20):
            await outcome(svc, iss.sign(good_claims(now)))
        check("20 logins fetch the key set once", iss.fetches == 1, iss.fetches)
        for i in range(30):
            await outcome(svc, iss.sign(good_claims(now), key=other, kid=f"junk-{i}"))
        check("30 tokens with unknown kids cause no extra fetch within a minute", iss.fetches == 1, iss.fetches)
        # rotation: the issuer publishes a new key
        new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        iss.jwks = {"keys": [jwk_of(new_key, "unit-key-2")]}
        res = await outcome(svc, iss.sign(good_claims(now), key=new_key, kid="unit-key-2"))
        check("a rotated key is not picked up inside the one-minute window", isinstance(res, Forged), res)
        clock[0] += 61
        res = await outcome(svc, iss.sign(good_claims(now), key=new_key, kid="unit-key-2"))
        check("  ... and is after it", getattr(res, "client_id", None) == CID and iss.fetches == 2, (res, iss.fetches))
        res = await outcome(svc, iss.sign(good_claims(now)))
        check("  ... and the withdrawn key stops working", isinstance(res, Forged), res)
        # the issuer goes down
        iss.status = 500
        clock[0] += 1800
        res = await outcome(svc, iss.sign(good_claims(now), key=new_key, kid="unit-key-2"))
        check("keys fetched under an hour ago keep working while the issuer is down",
              getattr(res, "client_id", None) == CID, res)
        clock[0] += 1900
        res = await outcome(svc, iss.sign(good_claims(now), key=new_key, kid="unit-key-2"))
        check("after an hour without a refresh the login fails closed", isinstance(res, Unavailable), res)
        before = iss.fetches
        for _ in range(10):
            await outcome(svc, iss.sign(good_claims(now), key=new_key, kid="unit-key-2"))
        check("  ... retrying at most once a minute", iss.fetches == before, (before, iss.fetches))
        iss.status = 200
        clock[0] += 61
        res = await outcome(svc, iss.sign(good_claims(now), key=new_key, kid="unit-key-2"))
        check("  ... and recovers when the issuer is back", getattr(res, "client_id", None) == CID, res)

        down = FakeIssuer()
        down.status = 503
        res = await outcome(down.service(), down.sign(good_claims(now)))
        check("an issuer that is down at the first login: fail closed", isinstance(res, Unavailable), res)
        redirect = FakeIssuer()
        redirect.status = 302
        res = await outcome(redirect.service(), redirect.sign(good_claims(now)))
        check("a JWKS redirect is not followed", isinstance(res, Unavailable) and redirect.fetches == 1, res)
        huge = FakeIssuer()
        huge.raw = b'{"keys": [' + b" " * (agent_login.MAX_JWKS_BYTES + 10) + b"]}"
        res = await outcome(huge.service(), huge.sign(good_claims(now)))
        check("an oversized key set is refused", isinstance(res, Unavailable), res)
        empty = FakeIssuer()
        empty.jwks = {"keys": [{"kty": "oct", "k": "c2VjcmV0", "kid": empty.kid}]}
        res = await outcome(empty.service(), empty.sign(good_claims(now)))
        check("a key set with no usable key: fail closed", isinstance(res, Unavailable), res)
        notjson = FakeIssuer()
        notjson.raw = b"<html>login</html>"
        res = await outcome(notjson.service(), notjson.sign(good_claims(now)))
        check("a key set that is not JSON: fail closed", isinstance(res, Unavailable), res)
    finally:
        agent_login.time.monotonic = real_monotonic


# ------------------------------------------------------------------ live

C1, C2, C3 = (f"mockClient000000000000000000000{i}" for i in (1, 2, 3))
SECRETS = {C1: "mock-secret-one", C2: "mock-secret-two", C3: "mock-secret-three"}
UNMAPPED = "nobodyClient00000000000000000001"


class Live:
    def __init__(self) -> None:
        self.base = os.environ.get("AGENTGATE_URL", "http://broker:8000").rstrip("/")
        self.issuer = os.environ.get("MOCK_ISSUER_URL", "http://mock-issuer:9191").rstrip("/")
        self.audience = os.environ.get("AUTH0_AUDIENCE", "https://agentgate.local/api")
        self.admin_key = os.environ["AGENTGATE_ADMIN_KEY"]
        self.orch_key = os.environ["AGENTGATE_ORCHESTRATOR_KEY"]
        self.http = httpx.Client(timeout=60, trust_env=False)
        self.iss_name = self.http.get(f"{self.issuer}/stats").json()["issuer"]

    @staticmethod
    def _j(r):
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, {}

    def admin(self, method: str, path: str, body=None, via: str | None = None, **params):
        headers = {"X-Admin-Key": self.admin_key, **({"X-Admin-Via": via} if via else {})}
        return self._j(self.http.request(method, f"{self.base}{path}", json=body, headers=headers, params=params or None))

    def mint(self, agent: str, scopes: list[str], session_id: str | None = None):
        body = {"agent_id": agent, "task": "day13 test", "scopes": scopes, **({"session_id": session_id} if session_id else {})}
        return self._j(self.http.post(f"{self.base}/tokens", json=body, headers={"X-Orchestrator-Key": self.orch_key}))

    def auth0(self, client_id: str, audience: str | None = None) -> str:
        r = self.http.post(f"{self.issuer}/oauth/token", json={
            "grant_type": "client_credentials", "client_id": client_id, "client_secret": SECRETS[client_id],
            "audience": audience or self.audience})
        return r.json()["access_token"]

    def sign(self, claims: dict, **kw) -> str:
        return self.http.post(f"{self.issuer}/sign", json={"claims": claims, **kw}).json()["token"]

    def claims(self, client_id: str = C1, **over) -> dict:
        now = int(time.time())
        claims = {"iss": self.iss_name, "sub": f"{client_id}@clients", "aud": self.audience, "iat": now - 5,
                  "exp": now + 3600, "gty": "client-credentials", "azp": client_id}
        claims.update(over)
        return {k: v for k, v in claims.items() if v is not None}

    def login(self, bearer: str | None, scopes: list[str], session_id: str | None = None, **extra):
        body = {"task": "day13 test", "scopes": scopes, **({"session_id": session_id} if session_id else {}), **extra}
        headers = {"Authorization": f"Bearer {bearer}"} if bearer is not None else {}
        return self._j(self.http.post(f"{self.base}/tokens/agent", json=body, headers=headers))

    def call(self, token: str, tool: str, args: dict):
        return self._j(self.http.post(f"{self.base}/tools/{tool}", json={"args": args},
                                      headers={"Authorization": f"Bearer {token}"}))

    def issued(self) -> int:
        return self.http.get(f"{self.issuer}/stats").json()["tokens_issued"]


AGENTS = {"d13-bot": ("shiwin", C1), "d13-peer": ("shiwin", C2), "d13-other": ("d13alex", C3)}
GRANTS = {"d13-bot": [("query_customers", "direct"), ("read_web", "direct"), ("send_email", "direct_if_untainted")],
          "d13-peer": [("query_customers", "direct")], "d13-other": [("query_customers", "direct")]}


async def live() -> None:
    import asyncpg
    g = Live()
    db = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        await _live(g, db)
    finally:
        for agent, grants in GRANTS.items():
            for tool, _ in grants:
                g.admin("DELETE", f"/agents/{agent}/grants", tool=tool)
        await db.close()


async def head(db) -> int:
    return await db.fetchval("SELECT coalesce(max(id), 0) FROM audit_events")


async def event(db, audit_id) -> dict:
    row = await db.fetchrow("SELECT * FROM audit_events WHERE id = $1", audit_id)
    return dict(row) if row else {}


async def _live(g: Live, db) -> None:
    print("live: setup")
    status, health = g._j(g.http.get(f"{g.base}/health"))
    check("the broker reports agent login is on", health.get("agent_login") == "auth0", health)
    for agent, (owner, client) in AGENTS.items():
        status, body = g.admin("POST", "/agents", {"id": agent, "owner": owner, "auth0_client_id": client})
        if status == 409:      # an earlier run registered it
            g.admin("PATCH", f"/agents/{agent}", {"status": "active"})
            status, body = g.admin("PATCH", f"/agents/{agent}", {"auth0_client_id": client})
        check(f"{agent} is registered and mapped to its Auth0 client", status in (200, 201)
              and body.get("auth0_client_id") == client and body.get("login") == "auth0", body)
        for tool, mode in GRANTS[agent]:
            status, body = g.admin("POST", f"/agents/{agent}/grants", {"tool": tool, "mode": mode})
            check(f"  ... granted {tool} ({mode})", status in (201, 409), body)
    time.sleep(1.2)     # a token minted in the same second as a login change counts as revoked
    # Taint follows an agent while it holds a live token in a tainted session: forget an earlier run's.
    await db.execute("UPDATE tokens SET expires_at = now() - interval '1 second' WHERE agent_id LIKE 'd13-%'")

    print("live: the done check, a standalone script with only a client id and secret")
    script = HERE.parent.parent / "examples" / "agent_login.py"
    if not script.exists():
        script = Path("/srv/examples/agent_login.py")
    if script.exists():
        with tempfile.TemporaryDirectory() as tmp:
            env = {"PATH": os.environ.get("PATH", ""), "AUTH0_TOKEN_URL": f"{g.issuer}/oauth/token",
                   "AUTH0_CLIENT_ID": C1, "AUTH0_CLIENT_SECRET": SECRETS[C1], "AUTH0_AUDIENCE": g.audience,
                   "AGENTGATE_URL": g.base, "NO_PROXY": "*", "no_proxy": "*"}
            cmd = [sys.executable, str(script), "--tool", "query_customers", "--args", '{"limit": 2}',
                   "--cache", str(Path(tmp) / "cache.json")]
            before = g.issued()
            run = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120)
            check("the script logs in and its call is allowed (exit 0)", run.returncode == 0, run.stdout + run.stderr)
            check("  ... as d13-bot", "logged in as agent 'd13-bot'" in run.stdout, run.stdout)
            check("  ... and gets the tool's result", '"customers"' in run.stdout, run.stdout)
            check("  ... the orchestrator and admin keys are not in its environment",
                  not any("ORCHESTRATOR" in k or "ADMIN" in k for k in env))
            run2 = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120)
            check("a second run uses the cached Auth0 token", run2.returncode == 0 and "cached token" in run2.stdout,
                  run2.stdout + run2.stderr)
            check("  ... so two runs cost one Auth0 token", g.issued() - before == 1, g.issued() - before)
            bad = subprocess.run([*cmd, "--fresh"], env={**env, "AUTH0_CLIENT_SECRET": "wrong"}, capture_output=True,
                                 text=True, timeout=120)
            check("a wrong client secret fails at Auth0, before AgentGate", bad.returncode != 0 and "auth0: no token" in
                  (bad.stdout + bad.stderr), bad.stdout + bad.stderr)
    else:
        print("  (skipped: examples/agent_login.py is not mounted)")

    print("live: logging in")
    bearer = g.auth0(C1)
    status, tok = g.login(bearer, ["query_customers"])
    check("a valid Auth0 token gets an AgentGate token (201)", status == 201 and tok.get("agent_id") == "d13-bot", tok)
    check("  ... marked as the agent's own login", tok.get("login") == "auth0")
    check("  ... for a new, clean session", tok.get("session_tainted") is False and tok.get("session_id"))
    row = await db.fetchrow("SELECT login, agent_id FROM tokens WHERE jti = $1", uuid.UUID(tok["jti"]))
    check("  ... recorded in the tokens table", row and row["login"] == "auth0" and row["agent_id"] == "d13-bot", row)
    ev = await db.fetchrow("SELECT * FROM audit_events WHERE jti = $1 AND event_type = 'token_issued'", tok["jti"])
    check("  ... audited as token_issued with 'login: auth0'", ev and ev["reason"].endswith("; login: auth0")
          and ev["agent_id"] == "d13-bot", dict(ev) if ev else None)
    srow = await db.fetchrow("SELECT owner, created_by FROM sessions WHERE id = $1", uuid.UUID(tok["session_id"]))
    check("  ... the session belongs to the agent's owner", srow and srow["owner"] == "user:shiwin"
          and srow["created_by"] == "d13-bot", dict(srow) if srow else None)
    claims = jwt.decode(tok["access_token"], options={"verify_signature": False})
    check("  ... the AgentGate token is the usual one (EdDSA, sub = agent, 10 minutes)",
          jwt.get_unverified_header(tok["access_token"])["alg"] == "EdDSA" and claims["sub"] == "d13-bot"
          and claims["exp"] - claims["iat"] == tok["expires_in"], claims)
    status, body = g.call(tok["access_token"], "query_customers", {"limit": 1})
    check("the granted tool is allowed", status == 200 and body.get("decision") == "allow", body)
    status, body = g.call(tok["access_token"], "send_email", {"to": "a@agentgate.example", "subject": "s", "body": "b"})
    check("a tool outside the token's scopes is denied", body.get("decision") == "deny", body)
    before = g.issued()
    oks = [g.login(bearer, ["query_customers"])[0] for _ in range(5)]
    check("the same Auth0 token logs in again and again", oks == [201] * 5, oks)
    check("  ... without costing another Auth0 token", g.issued() == before)
    status, body = g.login(bearer, ["transfer_funds"])
    check("a scope the agent has no grant for is refused (403) and audited", status == 403 and body.get("audit_id")
          and "may not hold" in body.get("reason", ""), body)
    status, body = g.login(bearer, ["no.such_tool"])
    check("an unknown tool scope is refused (400)", status == 400, body)
    status, body = g.login(bearer, [])
    check("no scopes is refused (400)", status == 400, body)
    status, body = g.login(bearer, ["query_customers"], agent_id="finance")
    check("the body can't name an agent (400)", status == 400, body)
    status, body = g.login(g.auth0(C2), ["send_email"])
    check("another agent's client can't get this agent's grants", status == 403, body)
    by_id = {a["id"]: a for a in g.http.get(f"{g.base}/agents", headers={"X-Admin-Key": g.admin_key}).json()}
    check("GET /agents shows who logs in how", by_id["d13-bot"]["login"] == "auth0"
          and by_id["d13-bot"]["auth0_client_id"] == C1 and by_id["researcher"]["login"] == "orchestrator"
          and by_id["researcher"]["auth0_client_id"] is None, by_id.get("d13-bot"))

    print("live: refused logins")
    own = tok["access_token"]

    async def refused(name: str, bearer, want_status: int, audited: bool, needle: str = "") -> dict:
        h0 = await head(db)
        status, body = g.login(bearer, ["query_customers"])
        ok = status == want_status and "access_token" not in body and needle in str(body.get("reason", ""))
        h1 = await head(db)
        if audited:
            ev = await event(db, body.get("audit_id"))
            ok = ok and h1 == h0 + 1 and ev.get("event_type") == "token_denied" and ev.get("decision") == "deny"
        else:
            ok = ok and h1 == h0 and "audit_id" not in body
        check(f"{name} -> {want_status}, {'audited' if audited else 'not audited'}", ok, (status, body, h0, h1))
        return body

    await refused("wrong audience", g.auth0(C1, audience="https://some-other-api.example"), 401, True, "another audience")
    body = await refused("expired token", g.sign(g.claims(iat=int(time.time()) - 7200, exp=int(time.time()) - 60)),
                         401, True, "expired")
    ev = await event(db, body.get("audit_id"))
    check("  ... the audit row names the agent and the Auth0 client", ev.get("agent_id") == "d13-bot" and C1 in ev.get("reason", ""), ev)
    await refused("token older than the maximum age", g.sign(g.claims(iat=int(time.time()) - 90000)), 401, True, "older")
    await refused("another issuer's name", g.sign(g.claims(iss="https://evil.example/")), 401, True, "another issuer")
    await refused("a user's access token for the same API", g.sign(g.claims(sub="auth0|64f0c0ffee", gty=None)),
                  401, True, "machine-to-machine")
    body = await refused("an unmapped client", g.sign(g.claims(UNMAPPED)), 403, True, "not mapped")
    ev = await event(db, body.get("audit_id"))
    check("  ... the audit row names the client and no agent", ev.get("agent_id") is None and UNMAPPED in ev.get("reason", ""), ev)
    jwks = g.http.get(f"{g.issuer}/.well-known/jwks.json").json()["keys"][0]
    await refused("alg swap: none", unsigned(g.claims(), "none", jwks["kid"]), 401, False)
    await refused("alg swap: HS256 keyed with the issuer's public key",
                  hs256_with_public_key(g.claims(), jwks, jwks["kid"]), 401, False, "RS256")
    await refused("signed with a key the issuer doesn't publish", g.sign(g.claims(), key="unpublished"), 401, False)
    await refused("  ... also when it claims the published kid", g.sign(g.claims(), key="unpublished", kid=jwks["kid"]),
                  401, False, "bad signature")
    await refused("the agent's own AgentGate token used as a login", own, 401, False)
    await refused("garbage", "not-a-token", 401, False)
    await refused("no Authorization header", None, 401, False)
    r = g.http.post(f"{g.base}/tokens/agent", json={"task": "t", "scopes": ["query_customers"]},
                    headers={"Authorization": f"Basic {bearer}"})
    check("a valid token under another scheme (Basic) -> 401", r.status_code == 401, r.text)
    r = g.http.post(f"{g.base}/tokens", json={"agent_id": "d13-bot", "task": "t", "scopes": ["query_customers"]},
                    headers={"Authorization": f"Bearer {bearer}"})
    check("an Auth0 token is no orchestrator key", r.status_code == 401, r.text)
    status, body = g.call(bearer, "query_customers", {"limit": 1})
    check("an Auth0 token is no AgentGate token: it can't call a tool directly", status == 401, body)
    rows = await db.fetch("SELECT reason FROM audit_events ORDER BY id DESC LIMIT 60")
    check("no audit row holds a bearer token", not any(bearer.split(".")[2][:40] in r["reason"] or "eyJ" in r["reason"]
                                                      for r in rows))

    print("live: the orchestrator key can't speak for an agent that logs in itself")
    status, body = g.mint("d13-bot", ["query_customers"])
    check("POST /tokens for d13-bot -> 403, audited", status == 403 and "logs in as itself" in body.get("reason", "")
          and body.get("audit_id"), body)
    status, body = g.mint("researcher", ["read_web"])
    check("  ... and still works for the demo agents", status == 201, body)
    orch_session = body.get("session_id")

    print("live: sessions")
    status, peer = g.login(g.auth0(C2), ["query_customers"])
    check("d13-peer (same owner) logs in", status == 201, peer)
    status, joined = g.login(bearer, ["query_customers"], session_id=peer["session_id"])
    check("d13-bot may join a session started by an agent of the same owner", status == 201
          and joined.get("session_id") == peer["session_id"], joined)
    status, body = g.login(g.auth0(C3), ["query_customers"], session_id=peer["session_id"])
    check("an agent of another owner may not (403)", status == 403 and "may join" in body.get("reason", ""), body)
    foreign_reason = body.get("reason")
    status, body = g.login(bearer, ["query_customers"], session_id=str(uuid.uuid4()))
    check("an unknown session id gets the same answer (no probing)", status == 403 and body.get("reason") == foreign_reason, body)
    status, body = g.login(bearer, ["query_customers"], session_id=orch_session)
    check("an orchestrator's session can't be joined by a self-login agent", status == 403, body)
    status, body = g.login(bearer, ["query_customers"], session_id="not-a-uuid")
    check("a malformed session id -> 400", status == 400, body)
    status, body = g.mint("researcher", ["read_web"], session_id=peer["session_id"])
    check("the orchestrator can still place its agents in any session", status == 201, body)

    print("live: taint follows the agent")
    status, t1 = g.login(bearer, ["read_web", "send_email"])
    mail = {"to": "team@agentgate.example", "subject": "notes", "body": "hello"}
    status, body = g.call(t1["access_token"], "send_email", mail)
    check("clean session: the email is allowed", body.get("decision") == "allow", body)
    status, body = g.call(t1["access_token"], "read_web", {"url": "https://blog.example.net/agent-security-roundup"})
    check("the agent reads a web page (taints its session)", body.get("decision") == "allow" and body.get("session_tainted"), body)
    status, body = g.call(t1["access_token"], "send_email", mail)
    check("tainted session: the email is no longer allowed", body.get("decision") in ("deny", "escalate"), body)
    h0 = await head(db)
    status, t2 = g.login(bearer, ["send_email"])
    check("the agent logs in again for a fresh session ...", status == 201 and t2["session_id"] != t1["session_id"], t2)
    check("  ... which starts TAINTED", t2.get("session_tainted") is True and t2.get("tainted_by") == "read_web", t2)
    ev = await db.fetchrow("SELECT * FROM audit_events WHERE id > $1 AND event_type = 'session_tainted' AND session_id = $2",
                           h0, t2["session_id"])
    check("  ... with a session_tainted event that says why", ev and "carried over" in ev["reason"]
          and t1["session_id"][:8] in ev["reason"], dict(ev) if ev else None)
    status, body = g.call(t2["access_token"], "send_email", mail)
    check("  ... so the email is still not allowed (no laundering by re-login)", body.get("decision") in ("deny", "escalate"), body)
    status, peer2 = g.login(g.auth0(C2), ["query_customers"])
    status, body = g.login(bearer, ["send_email"], session_id=peer2["session_id"])
    check("joining a peer's clean session taints that session too", status == 201 and body.get("session_tainted") is True, body)
    status, body = g.login(g.auth0(C2), ["query_customers"], session_id=peer2["session_id"])
    check("  ... which the peer then sees", body.get("session_tainted") is True, body)
    status, body = g.login(g.auth0(C2), ["query_customers"])
    check("  ... and carries on: the peer shared a tainted session, so its next session starts tainted too",
          status == 201 and body.get("session_tainted") is True, body)
    status, body = g.login(g.auth0(C3), ["query_customers"])
    check("another owner's agent is unaffected", status == 201 and body.get("session_tainted") is False, body)
    # once the tainted session's tokens have expired, a new session is clean (same as a new orchestrator run)
    await db.execute("UPDATE tokens SET expires_at = now() - interval '1 second' WHERE agent_id = 'd13-bot'")
    status, t3 = g.login(bearer, ["send_email"])
    check("after its tokens in tainted sessions expire, a new session is clean (documented limit)",
          status == 201 and t3.get("session_tainted") is False, t3)

    print("live: kill switch")
    status, t4 = g.login(bearer, ["query_customers"])
    status, body = g.call(t4["access_token"], "query_customers", {"limit": 1})
    check("before: the token works", status == 200, body)
    status, body = g.admin("PATCH", "/agents/d13-bot", {"status": "disabled", "reason": "day13 test"})
    check("kill switch on d13-bot", status == 200 and body.get("status") == "disabled", body)
    status, body = g.call(t4["access_token"], "query_customers", {"limit": 1})
    check("the live token dies at once (401)", status == 401, body)
    status, body = g.login(bearer, ["query_customers"])
    check("a new login is refused (403) and audited", status == 403 and "disabled" in body.get("reason", "")
          and body.get("audit_id"), body)
    status, body = g.admin("PATCH", "/agents/d13-bot", {"status": "active"})
    time.sleep(1.2)
    status, t5 = g.login(bearer, ["query_customers"])
    check("re-enabled: the agent can log in again", status == 201, t5)
    status, body = g.call(t4["access_token"], "query_customers", {"limit": 1})
    check("  ... the old token stays dead", status == 401, body)
    status, body = g.call(t5["access_token"], "query_customers", {"limit": 1})
    check("  ... the new one works", status == 200, body)

    print("live: changing an agent's login")
    status, body = g.admin("PATCH", "/agents/d13-peer", {"auth0_client_id": C1})
    check("a client already mapped to another agent is refused (409)", status == 409, body)
    status, body = g.admin("POST", "/agents", {"id": "d13-dup", "owner": "shiwin", "auth0_client_id": C1})
    check("  ... also when registering", status == 409 and body.get("error") == "client_in_use", body)
    check("  ... and no half-made agent is left", "d13-dup" not in {a["id"] for a in g.http.get(
        f"{g.base}/agents", headers={"X-Admin-Key": g.admin_key}).json()})
    for bad in ("short", "has space in it 000000", "x" * 65, "abc/def/ghi/jkl", ""):
        status, body = g.admin("PATCH", "/agents/d13-bot", {"auth0_client_id": bad})
        check(f"a malformed client id {bad[:12]!r} is refused (400)", status == 400, body)
    h0 = await head(db)
    status, body = g.admin("PATCH", "/agents/d13-bot", {"auth0_client_id": C1})
    check("setting the same client again changes nothing and writes no audit row", status == 200 and await head(db) == h0, body)
    status, body = g.call(t5["access_token"], "query_customers", {"limit": 1})
    check("  ... and revokes nothing", status == 200, body)
    status, body = g.admin("PATCH", "/agents/d13-bot", {"auth0_client_id": None}, via="admin-ui:auth0|d13tester")
    check("removing the login", status == 200 and body.get("login") == "orchestrator" and body.get("auth0_client_id") is None, body)
    ev = await event(db, body.get("audit_id"))
    check("  ... audited as agent_login_changed, with who did it", ev.get("event_type") == "agent_login_changed"
          and ev.get("approver") == "admin-ui:auth0|d13tester" and C1 in ev.get("reason", ""), ev)
    status, body = g.call(t5["access_token"], "query_customers", {"limit": 1})
    check("  ... revokes the tokens minted under the old login", status == 401, body)
    status, body = g.login(bearer, ["query_customers"])
    check("  ... the Auth0 client no longer maps to an agent (403)", status == 403 and "not mapped" in body.get("reason", ""), body)
    time.sleep(1.2)
    status, body = g.mint("d13-bot", ["query_customers"])
    check("  ... and the orchestrator key mints its tokens again", status == 201, body)
    orch_tok = body.get("access_token", "")
    status, body = g.admin("PATCH", "/agents/d13-bot", {"auth0_client_id": C1})
    check("mapping it again", status == 200 and body.get("login") == "auth0", body)
    status, body = g.call(orch_tok, "query_customers", {"limit": 1})
    check("  ... kills the token the orchestrator minted meanwhile", status == 401, body)
    time.sleep(1.2)
    status, body = g.login(bearer, ["query_customers"])
    check("  ... and the agent logs in as itself again", status == 201, body)

    chain = g.http.get(f"{g.base}/audit/verify").json()
    check("audit chain still valid", chain.get("valid") is True, chain)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--unit-only", action="store_true")
    args = ap.parse_args()
    asyncio.run(unit())
    if not args.unit_only:
        need = ("DATABASE_URL", "AGENTGATE_ORCHESTRATOR_KEY", "AGENTGATE_ADMIN_KEY")
        missing = [k for k in need if not os.environ.get(k)]
        if missing:
            print(f"setup: missing in the environment: {', '.join(missing)} (or pass --unit-only)")
            return 2
        asyncio.run(live())
    print(f"\n{COUNT - len(FAILED)}/{COUNT} checks passed" + (f"; FAILED: {', '.join(FAILED)}" if FAILED else ""))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
