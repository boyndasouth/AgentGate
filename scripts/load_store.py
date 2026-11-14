"""Load the AgentGate policy into a fresh OpenFGA store.

Steps
  1. Convert policy/model.fga to JSON (uses `fga` if installed, else the openfga/cli Docker image).
  2. Create a new store (with --replace, delete older stores of the same name first).
  3. Write the authorization model and the seed tuples from policy/tuples.yaml.
  4. Replay every check and list_objects case in policy/tests.fga.yaml against the live server.
  5. Save FGA_STORE_ID and FGA_MODEL_ID to .env for the broker (Day 2).

Usage (PowerShell, from the repo root, with `docker compose up -d` running):
  py -m pip install pyyaml
  py scripts/load_store.py --replace

Only dependency: PyYAML. HTTP calls use the OpenFGA REST API through urllib.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
POLICY = REPO / "policy"
WRITE_BATCH = 100  # OpenFGA's default max tuples per Write call


# ---------------------------------------------------------------- HTTP helpers
class FgaError(RuntimeError):
    pass


def call(api: str, method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        api.rstrip("/") + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise FgaError(f"{method} {path} -> {e.code}: {e.read().decode(errors='replace')}") from None
    except urllib.error.URLError as e:
        raise FgaError(f"Cannot reach OpenFGA at {api} ({e.reason}). Is `docker compose up -d` running?") from None


# ---------------------------------------------------------------- model DSL -> JSON
def model_to_json(model_file: Path) -> dict:
    """Use the fga CLI to transform the DSL; Python has no official OpenFGA DSL parser."""
    if shutil.which("fga"):
        cmd = ["fga", "model", "transform", "--file", str(model_file), "--output-format", "json"]
    elif shutil.which("docker"):
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{model_file.parent}:/policy:ro",
            "openfga/cli", "model", "transform",
            "--file", f"/policy/{model_file.name}", "--output-format", "json",
        ]
    else:
        sys.exit("Need either the fga CLI or Docker to convert model.fga to JSON.")

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"Model transform failed:\n{result.stderr or result.stdout}")
    model = json.loads(result.stdout)
    model.pop("id", None)
    return model


# ---------------------------------------------------------------- store setup
def list_stores(api: str) -> list[dict]:
    stores, token = [], ""
    while True:
        page = call(api, "GET", "/stores?page_size=50" + (f"&continuation_token={token}" if token else ""))
        stores += page.get("stores", [])
        token = page.get("continuation_token", "")
        if not token:
            return stores


def write_tuples(api: str, store_id: str, model_id: str, tuples: list[dict]) -> None:
    for i in range(0, len(tuples), WRITE_BATCH):
        call(api, "POST", f"/stores/{store_id}/write", {
            "authorization_model_id": model_id,
            "writes": {"tuple_keys": tuples[i:i + WRITE_BATCH]},
        })


# ---------------------------------------------------------------- replay tests
def outcome(can_invoke: bool | None, can_request: bool | None) -> str:
    if can_invoke:
        return "allow"
    if can_request:
        return "escalate"
    return "deny"


def replay_tests(api: str, store_id: str, model_id: str, tests_file: Path) -> int:
    suite = yaml.safe_load(tests_file.read_text(encoding="utf-8"))
    failures = 0
    for test in suite.get("tests", []):
        print(f"\n[{test['name']}]")
        for case in test.get("check", []) or []:
            got = {}
            for relation, expected in case["assertions"].items():
                body = {
                    "authorization_model_id": model_id,
                    "tuple_key": {"user": case["user"], "relation": relation, "object": case["object"]},
                }
                if case.get("context") is not None:
                    body["context"] = case["context"]
                allowed = call(api, "POST", f"/stores/{store_id}/check", body)["allowed"]
                got[relation] = allowed
                if allowed != expected:
                    failures += 1
                    print(f"  FAIL {case['user']} {relation} {case['object']} "
                          f"ctx={case.get('context')}: expected {expected}, got {allowed}")
            if "can_invoke" in got:
                label = outcome(got.get("can_invoke"), got.get("can_request_approval")).upper()
            else:
                label = ",".join(f"{r}={v}" for r, v in got.items())
            ctx = case.get("context") or {}
            print(f"  {label:<9} {case['user']:<17} -> {case['object']:<20} {json.dumps(ctx)}")

        for case in test.get("list_objects", []) or []:
            for relation, expected in case["assertions"].items():
                body = {
                    "authorization_model_id": model_id,
                    "type": case["type"],
                    "relation": relation,
                    "user": case["user"],
                }
                if case.get("context") is not None:
                    body["context"] = case["context"]
                objects = call(api, "POST", f"/stores/{store_id}/list-objects", body)["objects"]
                ok = sorted(objects) == sorted(expected)
                failures += 0 if ok else 1
                print(f"  {'ok' if ok else 'FAIL':<9} list {relation} for {case['user']} "
                      f"{json.dumps(case.get('context') or {})} -> {sorted(objects)}")
    return failures


# ---------------------------------------------------------------- .env
def save_env(env_file: Path, values: dict[str, str]) -> None:
    lines = env_file.read_text(encoding="utf-8").splitlines() if env_file.exists() else []
    remaining = dict(values)
    for i, line in enumerate(lines):
        key = line.split("=", 1)[0].strip()
        if key in remaining:
            lines[i] = f"{key}={remaining.pop(key)}"
    lines += [f"{k}={v}" for k, v in remaining.items()]
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------- main
def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api-url", default=os.getenv("FGA_API_URL", "http://localhost:8080"))
    parser.add_argument("--store-name", default="agentgate")
    parser.add_argument("--replace", action="store_true", help="delete existing stores with the same name first")
    parser.add_argument("--env-file", default=str(REPO / ".env"))
    parser.add_argument("--no-env", action="store_true", help="don't write IDs to .env")
    args = parser.parse_args()

    model = model_to_json(POLICY / "model.fga")
    tuples = yaml.safe_load((POLICY / "tuples.yaml").read_text(encoding="utf-8"))
    print(f"Model: {len(model['type_definitions'])} types, {len(model.get('conditions', {}))} conditions; "
          f"{len(tuples)} seed tuples")

    if args.replace:
        for store in list_stores(args.api_url):
            if store["name"] == args.store_name:
                call(args.api_url, "DELETE", f"/stores/{store['id']}")
                print(f"Deleted old store {store['id']}")

    store_id = call(args.api_url, "POST", "/stores", {"name": args.store_name})["id"]
    model_id = call(args.api_url, "POST", f"/stores/{store_id}/authorization-models", model)["authorization_model_id"]
    write_tuples(args.api_url, store_id, model_id, tuples)
    print(f"Store {args.store_name}: FGA_STORE_ID={store_id}  FGA_MODEL_ID={model_id}")

    failures = replay_tests(args.api_url, store_id, model_id, POLICY / "tests.fga.yaml")

    if not args.no_env:
        save_env(Path(args.env_file), {"FGA_STORE_ID": store_id, "FGA_MODEL_ID": model_id})
        print(f"\nSaved FGA_STORE_ID and FGA_MODEL_ID to {args.env_file}")

    if failures:
        sys.exit(f"\n{failures} assertion(s) failed against the live store.")
    print("All live checks match tests.fga.yaml.")


if __name__ == "__main__":
    try:
        main()
    except FgaError as err:
        sys.exit(str(err))
