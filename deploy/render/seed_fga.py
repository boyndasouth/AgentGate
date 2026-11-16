"""Sync OpenFGA's store at container boot (Render deploy).

OpenFGA runs inside the broker container. Day 10: its tuples persist in Postgres (an `openfga`
role and schema in Supabase) when FGA_DB_PASSWORD is set, because delegations are tuples written at
runtime. So at every boot this script SYNCS rather than seeds:
  1. waits for OpenFGA to be healthy,
  2. finds the store named "agentgate" (creates it on the first boot),
  3. reuses the latest authorization model if it equals policy/model.json, else writes it,
  4. makes the seed tuples on tool:* and agent:* objects match policy/tuples.yaml exactly
     (deletes stale or changed ones, writes missing ones) and never touches delegation:* tuples,
  5. replays sanity checks (fails the boot if policy is wrong),
  6. prints `export FGA_STORE_ID=... FGA_MODEL_ID=...` for start.sh to eval.
With the memory datastore (no FGA_DB_PASSWORD) the same steps simply start from empty.

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


SEED_PREFIXES = ("tool:", "agent:")     # objects tuples.yaml owns; everything else (delegation:*) is runtime data


def find_store() -> tuple[str, bool]:
    token = ""
    while True:
        page = call("GET", "/stores?page_size=100" + (f"&continuation_token={token}" if token else ""))
        for st in page.get("stores", []):
            if st["name"] == "agentgate":
                return st["id"], False
        token = page.get("continuation_token") or ""
        if not token:
            break
    return call("POST", "/stores", {"name": "agentgate"})["id"], True


def _prune(v):
    """Drop empty values: the API echoes defaults (null metadata, "" module, [] generic types)
    that `fga model transform` leaves out, so equal models must compare equal without them."""
    if isinstance(v, dict):
        v = {k: _prune(x) for k, x in v.items()}
        return {k: x for k, x in v.items() if x not in (None, "", [], {})}
    if isinstance(v, list):
        return [_prune(x) for x in v]
    return v


def same_model(a: dict, b: dict) -> bool:
    pick = lambda m: json.dumps(_prune({k: m.get(k) for k in ("schema_version", "type_definitions", "conditions")}),
                                sort_keys=True)
    return pick(a) == pick(b)


def sync_model(store: str, model_json: dict) -> tuple[str, bool]:
    models = call("GET", f"/stores/{store}/authorization-models?page_size=1").get("authorization_models", [])
    if models and same_model(models[0], model_json):
        return models[0]["id"], False
    return call("POST", f"/stores/{store}/authorization-models", model_json)["authorization_model_id"], True


def read_all(store: str) -> list[dict]:
    out, token = [], ""
    while True:
        body = {"page_size": 100, **({"continuation_token": token} if token else {})}
        page = call("POST", f"/stores/{store}/read", body)
        out.extend(t["key"] for t in page.get("tuples", []))
        token = page.get("continuation_token") or ""
        if not token:
            return out


def ident(t: dict) -> str:
    """A tuple's full identity, condition included: a changed condition counts as a different tuple."""
    cond = t.get("condition") or {}
    return json.dumps([t["user"], t["relation"], t["object"], cond.get("name"), cond.get("context") or {}],
                      sort_keys=True)


def sync_tuples(store: str, model: str, desired: list[dict]) -> tuple[int, int, int]:
    """Make the tool:*/agent:* tuples equal `desired`. Returns (written, deleted, runtime_kept)."""
    current = read_all(store)
    seed_now = [t for t in current if t["object"].startswith(SEED_PREFIXES)]
    want = {ident(t): t for t in desired}
    have = {ident(t): t for t in seed_now}
    stale = [t for k, t in have.items() if k not in want]
    missing = [t for k, t in want.items() if k not in have]
    # Deletes first (a changed condition is delete + write of the same user/relation/object).
    for i in range(0, len(stale), 100):
        call("POST", f"/stores/{store}/write", {"authorization_model_id": model, "deletes": {"tuple_keys": [
            {k: t[k] for k in ("user", "relation", "object")} for t in stale[i:i + 100]]}})
    for i in range(0, len(missing), 100):
        call("POST", f"/stores/{store}/write", {"authorization_model_id": model,
                                                "writes": {"tuple_keys": missing[i:i + 100]}})
    return len(missing), len(stale), len(current) - len(seed_now)


def main() -> None:
    wait_healthy()

    with open(os.path.join(POLICY_DIR, "model.json"), encoding="utf-8") as f:
        model_json = json.load(f)
    with open(os.path.join(POLICY_DIR, "tuples.yaml"), encoding="utf-8") as f:
        tuples = yaml.safe_load(f)

    store, new_store = find_store()
    model, new_model = sync_model(store, model_json)
    written, deleted, kept = sync_tuples(store, model, [to_tuple_key(t) for t in tuples])
    log(f"store={store} ({'new' if new_store else 'existing'}) model={model} ({'new' if new_model else 'unchanged'}) "
        f"seed tuples={len(tuples)} (+{written} -{deleted}) runtime tuples kept={kept}")

    clean = {"amount": 40.0, "session_tainted": False, "host": "", "recipient_domain": "", "payee": "acct_acme_supplies", "invoice_matches": True}
    big = {"amount": 5000.0, "session_tainted": False, "host": "", "recipient_domain": "", "payee": "acct_acme_supplies", "invoice_matches": False}
    tainted = {"amount": 0.0, "session_tainted": True, "host": "", "recipient_domain": "", "payee": "", "invoice_matches": False}
    tainted_ok_host = {"amount": 0.0, "session_tainted": True, "host": "example.com", "recipient_domain": "", "payee": "", "invoice_matches": False}
    tainted_bad_host = {"amount": 0.0, "session_tainted": True, "host": "collect.partner-archive.example", "recipient_domain": "", "payee": "", "invoice_matches": False}
    internal = {"amount": 0.0, "session_tainted": False, "host": "", "recipient_domain": "agentgate.example", "payee": "", "invoice_matches": False}
    outside = {"amount": 0.0, "session_tainted": False, "host": "", "recipient_domain": "partner-archive.example", "payee": "", "invoice_matches": False}
    new_payee = {**clean, "payee": "ACCT-99-ATTACKER"}            # matching invoice, unknown payee
    no_invoice = {**clean, "invoice_matches": False}             # known payee, no open invoice (G05)
    expectations = [
        ("agent:finance", "can_invoke", "tool:transfer_funds", clean, True),
        ("agent:finance", "can_invoke", "tool:transfer_funds", big, False),
        ("agent:finance", "can_request_approval", "tool:transfer_funds", big, True),
        ("agent:finance", "can_invoke", "tool:transfer_funds", new_payee, False),
        ("agent:finance", "can_request_approval", "tool:transfer_funds", new_payee, True),
        ("agent:finance", "can_invoke", "tool:transfer_funds", no_invoice, False),
        ("agent:finance", "can_request_approval", "tool:transfer_funds", no_invoice, True),
        ("agent:mailer", "can_invoke", "tool:send_email", tainted, False),
        ("agent:mailer", "can_request_approval", "tool:send_email", tainted, True),
        ("agent:researcher", "can_request_approval", "tool:transfer_funds", clean, False),
        ("agent:researcher", "can_invoke", "tool:read_web", tainted_ok_host, True),
        ("agent:researcher", "can_invoke", "tool:read_web", tainted_bad_host, False),
        ("agent:mailer", "can_invoke", "tool:send_email", internal, True),
        ("agent:mailer", "can_invoke", "tool:send_email", outside, False),
        ("agent:mailer", "can_request_approval", "tool:send_email", outside, True),
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
