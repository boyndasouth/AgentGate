"""An agent that logs in to AgentGate as itself (Day 13). Standard library only.

All it holds is an Auth0 machine-to-machine client id and secret. It never sees the
orchestrator key, the admin key, or any upstream credential.

  1. Auth0: client credentials grant -> an Auth0 access token for the AgentGate API.
     The token is cached in a file until shortly before it expires. Auth0's Free plan
     counts every M2M token it issues (about 1,000 a month), so don't fetch one per run.
  2. AgentGate: POST /tokens/agent with that token -> a 10-minute AgentGate token,
     scoped to the tools this task needs.
  3. Call the tool through the gate.

Settings, from the environment or from --env-file (KEY=value lines):
  AUTH0_DOMAIN          dev-abc123.us.auth0.com
  AUTH0_CLIENT_ID       the M2M application's Client ID (also set on the agent in AgentGate)
  AUTH0_CLIENT_SECRET   its Client Secret
  AUTH0_AUDIENCE        the AgentGate API identifier in Auth0 (same value the broker has)
  AGENTGATE_URL         https://agentgate-broker.onrender.com

Run:
  python examples/agent_login.py --env-file .env.agent --tool query_customers --args '{"limit": 2}'
  # PowerShell: quote the JSON as '{\"limit\": 2}' or leave --args out.

Exit code: 0 the call was allowed, 1 it was denied or sent for approval, 2 login failed.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CACHE_FILE = ".agentgate-token-cache.json"
EXPIRY_MARGIN = 120     # seconds: stop using a cached Auth0 token this long before it expires


def read_env_file(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def post_json(url: str, body: dict, headers: dict[str, str] | None = None, timeout: float = 90.0) -> tuple[int, dict]:
    """POST JSON, return (status, parsed body). Never raises on an HTTP status."""
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Accept": "application/json",
                                          **(headers or {})})
    context = ssl.create_default_context() if url.startswith("https://") else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    try:
        parsed = json.loads(raw) if raw else {}
    except ValueError:
        parsed = {"reason": raw[:200].decode(errors="replace")}
    return status, parsed if isinstance(parsed, dict) else {"items": parsed}


def auth0_token(cfg: dict[str, str], cache_path: Path, fresh: bool = False) -> str:
    """The Auth0 access token for this client: from the cache file, else from Auth0."""
    key = f"{cfg['token_url']}|{cfg['AUTH0_CLIENT_ID']}|{cfg['AUTH0_AUDIENCE']}"
    if not fresh and cache_path.exists():
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            cached = {}
        if cached.get("key") == key and cached.get("expires_at", 0) - EXPIRY_MARGIN > time.time():
            print(f"auth0: using the cached token (valid for another {int(cached['expires_at'] - time.time())} s)")
            return cached["access_token"]
    status, body = post_json(cfg["token_url"], {
        "grant_type": "client_credentials", "client_id": cfg["AUTH0_CLIENT_ID"],
        "client_secret": cfg["AUTH0_CLIENT_SECRET"], "audience": cfg["AUTH0_AUDIENCE"]})
    if status != 200 or "access_token" not in body:
        # Auth0's error text names the problem (wrong secret, client not authorized for the API).
        raise SystemExit(f"auth0: no token (HTTP {status}): {body.get('error_description') or body.get('error') or body}")
    expires_at = time.time() + int(body.get("expires_in", 0))
    try:
        cache_path.write_text(json.dumps({"key": key, "access_token": body["access_token"],
                                          "expires_at": expires_at}), encoding="utf-8")
        os.chmod(cache_path, 0o600)       # it is a credential; no effect on Windows
    except OSError as exc:
        print(f"auth0: couldn't write the token cache ({exc}); the next run will ask Auth0 again")
    print(f"auth0: got a new token (valid for {int(body.get('expires_in', 0))} s), cached in {cache_path}")
    return body["access_token"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--env-file", help="file with KEY=value lines (kept out of git, e.g. .env.agent)")
    ap.add_argument("--tool", default="query_customers")
    ap.add_argument("--args", default="{}", help="the tool's arguments as JSON")
    ap.add_argument("--task", default="example: an agent logging in as itself")
    ap.add_argument("--session-id", help="join a session this agent may use, instead of starting one")
    ap.add_argument("--cache", default=CACHE_FILE, help=f"Auth0 token cache file (default {CACHE_FILE})")
    ap.add_argument("--fresh", action="store_true", help="ignore the cache and ask Auth0 for a new token")
    opts = ap.parse_args()

    cfg = {**(read_env_file(opts.env_file) if opts.env_file else {}),
           **{k: v for k, v in os.environ.items() if k.startswith(("AUTH0_", "AGENTGATE_"))}}
    need = ["AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET", "AUTH0_AUDIENCE", "AGENTGATE_URL"]
    missing = [k for k in need if not cfg.get(k)]
    if not cfg.get("AUTH0_DOMAIN") and not cfg.get("AUTH0_TOKEN_URL"):
        missing.append("AUTH0_DOMAIN")
    if missing:
        print(f"missing settings: {', '.join(missing)}")
        return 2
    # AUTH0_TOKEN_URL is only for the local mock issuer (http://mock-issuer:9191/oauth/token).
    cfg["token_url"] = cfg.get("AUTH0_TOKEN_URL") or f"https://{cfg['AUTH0_DOMAIN']}/oauth/token"
    try:
        tool_args = json.loads(opts.args)
        assert isinstance(tool_args, dict)
    except (ValueError, AssertionError):
        print("--args must be a JSON object")
        return 2
    gate = cfg["AGENTGATE_URL"].rstrip("/")

    # 1. Auth0
    bearer = auth0_token(cfg, Path(opts.cache), fresh=opts.fresh)

    # 2. AgentGate: who we are comes from the Auth0 token, so the body has no agent id.
    body = {"task": opts.task, "scopes": [opts.tool], **({"session_id": opts.session_id} if opts.session_id else {})}
    status, login = post_json(f"{gate}/tokens/agent", body, {"Authorization": f"Bearer {bearer}"})
    if status == 401 and not opts.fresh and "expired" in str(login.get("reason", "")):
        bearer = auth0_token(cfg, Path(opts.cache), fresh=True)     # the cached token ran out early
        status, login = post_json(f"{gate}/tokens/agent", body, {"Authorization": f"Bearer {bearer}"})
    if status != 201:
        print(f"agentgate: login refused (HTTP {status}): {login.get('reason') or login}")
        return 2
    print(f"agentgate: logged in as agent '{login['agent_id']}', session {login['session_id']}"
          f"{' (TAINTED by ' + str(login.get('tainted_by')) + ')' if login.get('session_tainted') else ''}, "
          f"scopes {login['scopes']}, token valid {login['expires_in']} s")

    # 3. The tool call, through the gate.
    status, result = post_json(f"{gate}/tools/{urllib.parse.quote(opts.tool, safe='')}", {"args": tool_args},
                               {"Authorization": f"Bearer {login['access_token']}"})
    decision = result.get("decision", "error")
    print(f"agentgate: {opts.tool} -> {decision} (HTTP {status}): {result.get('reason')}")
    if decision == "allow":
        print(json.dumps(result.get("result"), indent=2)[:2000])
        return 0
    if decision == "escalate":
        print(f"waiting for a human: approval {result.get('approval_id')} expires at {result.get('expires_at')}. "
              "Poll GET /approvals/{id} with the same token; do not retry the call.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
