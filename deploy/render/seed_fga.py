"""Seed an in-memory OpenFGA at container boot (Render deploy).

OpenFGA runs inside the broker container with the memory datastore, so the
store is empty on every boot. This script:
  1. waits for OpenFGA to be healthy,
  2. creates a store, writes policy/model.json and policy/tuples.yaml,
  3. replays a few sanity checks (fails the boot if policy is wrong),
  4. prints `export FGA_STORE_ID=... FGA_MODEL_ID=...` for start.sh to eval.

Only stdout carries the export lines; all logging goes to stderr.
Stdlib + PyYAML only, same REST approach as scripts/load_store.py.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

import yaml

FGA = os.environ.get("FGA_LOCAL_URL", "http://127.0.0.1:8080")
POLICY_DIR = os.environ.get("POLICY_DIR", "/srv/policy")


def log(msg: str) -> None:
    print(f"[seed_fga] {msg}", file=sys.stderr, flush=True)


def call(method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        FGA + path, data=data, method=method, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raise SystemExit(f"[seed_fga] {method} {path} -> {e.code}: {e.read().decode()}")


def wait_healthy(timeout_s: float = 30) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(FGA + "/healthz", timeout=2) as resp:
                if json.loads(resp.read()).get("status") == "SERVING":
                    return
        except Exception:
            pass
        time.sleep(0.3)
    raise SystemExit("[seed_fga] OpenFGA did not become healthy in time")


def to_tuple_key(t: dict) -> dict:
    key = {"user": t["user"], "relation": t["relation"], "object": t["object"]}
    if "condition" in t:
        cond = {"name": t["condition"]["name"]}
        if t["condition"].get("context"):
            cond["context"] = t["condition"]["context"]
        key["condition"] = cond
    return key


def check(store: str, model: str, user: str, relation: str, obj: str, ctx: dict) -> bool:
    body = {
        "authorization_model_id": model,
        "tuple_key": {"user": user, "relation": relation, "object": obj},
        "context": ctx,
    }
    return call("POST", f"/stores/{store}/check", body)["allowed"]


def main() -> None:
    wait_healthy()

    with open(os.path.join(POLICY_DIR, "model.json"), encoding="utf-8") as f:
        model_json = json.load(f)
    with open(os.path.join(POLICY_DIR, "tuples.yaml"), encoding="utf-8") as f:
        tuples = yaml.safe_load(f)

    store = call("POST", "/stores", {"name": "agentgate"})["id"]
    model = call("POST", f"/stores/{store}/authorization-models", model_json)["authorization_model_id"]
    # OpenFGA accepts up to 100 tuples per write; the demo has 12.
    call("POST", f"/stores/{store}/write", {
        "authorization_model_id": model,
        "writes": {"tuple_keys": [to_tuple_key(t) for t in tuples]},
    })
    log(f"store={store} model={model} tuples={len(tuples)}")

    clean = {"amount": 40.0, "session_tainted": False, "host": ""}
    big = {"amount": 5000.0, "session_tainted": False, "host": ""}
    tainted = {"amount": 0.0, "session_tainted": True, "host": ""}
    tainted_ok_host = {"amount": 0.0, "session_tainted": True, "host": "example.com"}
    tainted_bad_host = {"amount": 0.0, "session_tainted": True, "host": "collect.partner-archive.example"}
    expectations = [
        ("agent:finance", "can_invoke", "tool:transfer_funds", clean, True),
        ("agent:finance", "can_invoke", "tool:transfer_funds", big, False),
        ("agent:finance", "can_request_approval", "tool:transfer_funds", big, True),
        ("agent:mailer", "can_invoke", "tool:send_email", tainted, False),
        ("agent:mailer", "can_request_approval", "tool:send_email", tainted, True),
        ("agent:researcher", "can_request_approval", "tool:transfer_funds", clean, False),
        ("agent:researcher", "can_invoke", "tool:read_web", tainted_ok_host, True),
        ("agent:researcher", "can_invoke", "tool:read_web", tainted_bad_host, False),
    ]
    for user, rel, obj, ctx, want in expectations:
        got = check(store, model, user, rel, obj, ctx)
        if got != want:
            raise SystemExit(f"[seed_fga] policy check failed: {user} {rel} {obj} {ctx} -> {got}, want {want}")
    log(f"{len(expectations)} sanity checks passed")

    print(f"export FGA_STORE_ID={store}")
    print(f"export FGA_MODEL_ID={model}")


if __name__ == "__main__":
    main()
