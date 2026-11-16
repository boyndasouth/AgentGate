"""Anchor the audit chain outside the database (Day 8).

The hash chain proves tampering only while whoever can write to the database is honest:
with write access you could edit a row and recompute every hash after it, and
GET /audit/verify would still say "intact". The fix is to write the chain head down
somewhere the database owner can't edit. This script does that with plain git:

  publish   ask the broker for a signed checkpoint (last id + hash) and append it to a
            JSON-lines file. The GitHub Action in .github/workflows/anchor.yml runs this on
            a schedule and commits the file to the `audit-anchors` branch.
  check     compare every published anchor with the live chain. If row N's hash is no
            longer what was anchored, the log was rewritten at or before row N.

  python scripts/anchor.py publish --url https://agentgate-broker.onrender.com --file anchors.jsonl
  python scripts/anchor.py check   --url https://agentgate-broker.onrender.com \
      --file https://raw.githubusercontent.com/boyndasouth/AgentGate/audit-anchors/anchors.jsonl

Both commands only use public endpoints (no keys): /audit/checkpoint, /audit/hashes,
/audit/verify, /.well-known/jwks.json. Stdlib only; if the `cryptography` package is
installed, checkpoint signatures (Ed25519) are verified too, otherwise that step is skipped
and the output says so (--require-signature turns the skip into an error).

Exit codes: 0 = ok, 1 = the chain does not match its anchors (or is broken), 2 = setup error.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CHECKPOINT_TYP = "agentgate-audit-checkpoint+jwt"
BATCH = 400          # /audit/hashes takes at most 500 ids


class SetupError(Exception):
    pass


# ---------------------------------------------------------------- HTTP


def get_json(url: str, *, wake_s: float = 0.0) -> dict:
    """GET a JSON document. With wake_s, retry connection errors and 5xx for that long
    (Render's free tier takes about a minute to wake up)."""
    deadline = time.monotonic() + wake_s
    while True:
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=90) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            if e.code < 500 or time.monotonic() >= deadline:
                raise SetupError(f"GET {url} -> HTTP {e.code}: {e.read()[:200].decode(errors='replace')}") from None
        except (urllib.error.URLError, OSError, ValueError) as e:
            if time.monotonic() >= deadline:
                raise SetupError(f"GET {url} failed: {e}") from None
        time.sleep(5)


def wait_healthy(base: str) -> None:
    deadline = time.monotonic() + 180
    while True:
        try:
            if get_json(base + "/health").get("status") == "ok":
                return
        except SetupError:
            pass
        if time.monotonic() >= deadline:
            raise SetupError(f"{base}/health did not answer in 3 minutes")
        time.sleep(5)


# ---------------------------------------------------------------- anchors file


def load_anchors(source: str) -> list[dict]:
    """Read anchors from a local path or an https URL. A missing local file is an empty list."""
    if source.startswith(("http://", "https://")):
        try:
            with urllib.request.urlopen(source, timeout=60) as resp:
                text = resp.read().decode("utf-8")
        except (urllib.error.URLError, OSError) as e:
            raise SetupError(f"cannot read anchors from {source}: {e}") from None
    else:
        path = Path(source)
        if not path.exists():
            return []
        text = path.read_text(encoding="utf-8")
    anchors = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            a = json.loads(line)
            anchors.append({"last_id": int(a["last_id"]), "head_hash": str(a["head_hash"]), "iat": int(a["iat"]),
                            "kid": str(a.get("kid", "")), "jws": str(a.get("jws", "")),
                            "anchored_at": str(a.get("anchored_at", ""))})
        except (ValueError, KeyError, TypeError) as e:
            raise SetupError(f"{source} line {n} is not a valid anchor: {e}") from None
    return anchors


def when(a: dict) -> str:
    return datetime.fromtimestamp(a["iat"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ---------------------------------------------------------------- signatures


def _b64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def signature_problem(a: dict, jwks: dict) -> str | None:
    """None if the anchor's JWS is a valid Ed25519 signature, by a key the broker publishes,
    over exactly the values in the anchor. Raises ImportError without `cryptography`."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        h64, p64, s64 = a["jws"].split(".")
        header, payload = json.loads(_b64url(h64)), json.loads(_b64url(p64))
    except (ValueError, TypeError):
        return "jws is not a compact JWS"
    if header.get("alg") != "EdDSA" or header.get("typ") != CHECKPOINT_TYP:
        return f"unexpected JWS header {header}"
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
    if key is None:
        return f"signed by key {header.get('kid')}, which the broker no longer publishes (key rotated?)"
    try:
        Ed25519PublicKey.from_public_bytes(_b64url(key["x"])).verify(_b64url(s64), f"{h64}.{p64}".encode())
    except (InvalidSignature, ValueError, KeyError):
        return "signature does not verify"
    for field in ("last_id", "head_hash", "iat"):
        if payload.get(field) != a[field]:
            return f"signed {field}={payload.get(field)!r} differs from the anchor's {a[field]!r}"
    return None


# ---------------------------------------------------------------- check


def check(base: str, anchors: list[dict], *, require_signature: bool, quiet: bool = False) -> list[str]:
    """Returns a list of problems (empty = the chain matches every anchor)."""
    say = (lambda *_: None) if quiet else print
    problems: list[str] = []

    # 1. The anchor list itself must be append-only: ids and times never go backwards.
    for prev, cur in zip(anchors, anchors[1:]):
        if cur["last_id"] < prev["last_id"] or cur["iat"] < prev["iat"]:
            problems.append(f"anchor list is out of order at id {cur['last_id']} ({when(cur)})")
        if cur["last_id"] == prev["last_id"] and cur["head_hash"] != prev["head_hash"]:
            problems.append(f"two anchors for row {cur['last_id']} with different hashes")

    # 2. Signatures: each anchor really is a statement the broker signed.
    try:
        jwks = get_json(base + "/.well-known/jwks.json")
        sig_problems = [(a, signature_problem(a, jwks)) for a in anchors]
        bad = [(a, p) for a, p in sig_problems if p]
        for a, p in bad:
            problems.append(f"anchor for row {a['last_id']} ({when(a)}): {p}")
        say(f"signatures: {len(anchors) - len(bad)}/{len(anchors)} valid (Ed25519, kid from /.well-known/jwks.json)")
    except ImportError:
        if require_signature:
            raise SetupError("--require-signature needs the `cryptography` package (pip install cryptography)") from None
        say("signatures: NOT checked (pip install cryptography to verify them)")

    # 3. Every anchored row must still have the hash that was written down.
    wanted = sorted({a["last_id"] for a in anchors if a["last_id"] > 0})
    live: dict[str, str] = {}
    for i in range(0, len(wanted), BATCH):
        ids = ",".join(map(str, wanted[i:i + BATCH]))
        live.update(get_json(f"{base}/audit/hashes?ids={ids}").get("hashes", {}))
    first_bad: dict | None = None
    for a in anchors:
        if a["last_id"] == 0:
            continue
        got = live.get(str(a["last_id"]))
        if got != a["head_hash"]:
            first_bad = first_bad or a
            problems.append(
                f"row {a['last_id']} is gone: it existed when anchored on {when(a)}" if got is None else
                f"row {a['last_id']} has hash {got[:16]}…, but {a['head_hash'][:16]}… was anchored on {when(a)}")
    if first_bad:
        ok_before = [a for a in anchors if a["last_id"] < first_bad["last_id"] and a["last_id"] > 0]
        since = f"after row {ok_before[-1]['last_id']} and " if ok_before else ""
        problems.append(f"=> the log was rewritten somewhere {since}at or before row {first_bad['last_id']}")
    say(f"anchors:    {len(wanted)} anchored rows compared with the live chain, "
        f"{sum(1 for a in anchors if a['last_id'] and live.get(str(a['last_id'])) != a['head_hash'])} mismatched")

    # 4. And the chain must still be internally consistent.
    v = get_json(base + "/audit/verify")
    if not v.get("valid"):
        problems.append(f"chain broken at row {v.get('first_broken_id')}: {v.get('problem')}")
    say(f"chain:      {'intact' if v.get('valid') else 'BROKEN'}, {v.get('checked')} rows checked")
    return problems


# ---------------------------------------------------------------- commands


def cmd_check(args: argparse.Namespace) -> int:
    base = args.url.rstrip("/")
    anchors = load_anchors(args.file)
    if not anchors:
        print(f"no anchors in {args.file} yet: nothing to compare (run `publish` first)")
        return 2
    wait_healthy(base)
    print(f"{len(anchors)} anchors, {when(anchors[0])} to {when(anchors[-1])}, last anchored row {anchors[-1]['last_id']}")
    problems = check(base, anchors, require_signature=args.require_signature)
    if problems:
        print("\nTAMPERING DETECTED (or anchors and broker don't belong together):")
        for p in problems:
            print("  - " + p)
        return 1
    print("\nOK: the chain is intact and passes through every published anchor.")
    return 0


def cmd_publish(args: argparse.Namespace) -> int:
    base = args.url.rstrip("/")
    if args.file.startswith(("http://", "https://")):
        raise SetupError("publish needs a local --file to append to")
    anchors = load_anchors(args.file)
    wait_healthy(base)

    # Never append to a history the chain no longer matches: that would bless a rewrite.
    if anchors:
        problems = check(base, anchors, require_signature=args.require_signature, quiet=True)
        if problems:
            print("NOT anchoring: the live chain does not match the anchors already published.")
            for p in problems:
                print("  - " + p)
            return 1

    cp = get_json(base + "/audit/checkpoint", wake_s=120)
    try:
        anchor = {"last_id": int(cp["last_id"]), "head_hash": str(cp["head_hash"]), "iat": int(cp["iat"]),
                  "kid": str(cp["kid"]), "jws": str(cp["jws"]),
                  "anchored_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    except (KeyError, ValueError, TypeError) as e:
        raise SetupError(f"unexpected /audit/checkpoint response ({e}); is the broker on v0.5.0 or later?") from None
    try:
        problem = signature_problem(anchor, get_json(base + "/.well-known/jwks.json"))
        if problem:
            print(f"NOT anchoring: checkpoint signature problem: {problem}")
            return 1
    except ImportError:
        if args.require_signature:
            raise SetupError("--require-signature needs the `cryptography` package") from None
        print("note: checkpoint signature not verified (cryptography not installed)")

    if anchors:
        last = anchors[-1]
        if anchor["last_id"] < last["last_id"]:
            print(f"NOT anchoring: the log got shorter (row {last['last_id']} anchored, head is now {anchor['last_id']}).")
            return 1
        if anchor["last_id"] == last["last_id"]:
            print(f"nothing new since {when(last)} (head is still row {last['last_id']}); file unchanged")
            return 0

    path = Path(args.file)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(anchor, separators=(",", ":")) + "\n")
    print(f"anchored row {anchor['last_id']} hash {anchor['head_hash'][:16]}… ({len(anchors) + 1} anchors in {args.file})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("publish", cmd_publish), ("check", cmd_check)):
        p = sub.add_parser(name)
        p.add_argument("--url", required=True, help="broker base URL")
        p.add_argument("--file", required=True, help="anchors file (check also accepts an https URL)")
        p.add_argument("--require-signature", action="store_true",
                       help="fail instead of skipping when signatures can't be verified")
        p.set_defaults(fn=fn)
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # Windows consoles
    try:
        return args.fn(args)
    except SetupError as e:
        print(f"setup error: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
