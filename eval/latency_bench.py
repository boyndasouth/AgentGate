"""Day 7: how much latency does the gate add to a tool call? p50 / p95 / p99.

  python eval/latency_bench.py                      # local broker, 300 rounds
  python eval/latency_bench.py --target render -n 100
  (or .\\scripts\\run_eval.ps1 bench [-Target render])

Method
- One keep-alive connection, sequential requests (latency, not throughput).
- Each round sends one request of every kind in turn (interleaved), so drift (GC, a noisy
  neighbour, Render waking up) hits every path equally. 30 warm-up rounds are discarded.
- Baseline = GET /.well-known/jwks.json: same server, same HTTP stack and network path, but
  no auth, no database, no policy. "Gate overhead" = path percentile minus baseline percentile.
  The mock tools themselves take microseconds, so a gated call minus the baseline is what
  AgentGate adds in front of a real tool: JWT verify, revocation + taint lookup, the OpenFGA
  check(s), and the hash-chained audit append.

Paths
  allow        mailer  query_customers {limit:1}       1 OpenFGA check + audit append
  allow_amount finance transfer_funds {amount:40}      invoice lookup + 1 conditional check + settle
  deny_scope   mailer  transfer_funds (not in token)   no OpenFGA; deny + audit append
  mint         POST /tokens (2 scopes, new session)    2 OpenFGA checks + 3 inserts + audit
               (measured every 5th round only, it creates a session each time)

Writes ~4 audit rows per round (~1,300 for the default run). Point it at a local or test
broker, not the database you demo from, unless you don't mind the rows.
Writes eval/results/latency-<target>-<utc>.json.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gate import REPO, Gate, load_config  # noqa: E402

TOKEN_REFRESH_S = 480   # tokens live 600 s; re-mint well before expiry


def pct(xs: list[float], p: float) -> float:
    """Nearest-rank percentile, in ms."""
    s = sorted(xs)
    k = max(0, min(len(s) - 1, round(p / 100 * len(s) + 0.5) - 1))
    return s[k] * 1000


def stats(xs: list[float]) -> dict:
    return {"n": len(xs), "p50": round(pct(xs, 50), 2), "p95": round(pct(xs, 95), 2),
            "p99": round(pct(xs, 99), 2), "mean": round(statistics.fmean(xs) * 1000, 2),
            "min": round(min(xs) * 1000, 2), "max": round(max(xs) * 1000, 2)}


class Tokens:
    def __init__(self, gate: Gate) -> None:
        self.gate, self.mailer, self.finance = gate, "", ""
        self.minted_at: float | None = None

    def fresh(self) -> None:
        if self.minted_at is not None and time.monotonic() - self.minted_at < TOKEN_REFRESH_S:
            return
        for agent, scopes in (("mailer", ["query_customers", "send_email"]), ("finance", ["transfer_funds"])):
            status, body, _ = self.gate.mint(agent, scopes, "latency benchmark")
            if status != 201:
                raise SystemExit(f"token for {agent} refused ({status}): {body.get('reason')} "
                                 "(kill switch on? re-enable the agent)")
            setattr(self, agent, body["access_token"])
        self.minted_at = time.monotonic()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", choices=["local", "render"], default="local")
    ap.add_argument("-n", "--rounds", type=int, default=300)
    ap.add_argument("--warmup", type=int, default=30)
    ap.add_argument("--no-save", action="store_true")
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # Windows consoles / redirects

    cfg = load_config(args.target)
    gate = Gate(cfg)
    health = gate.wait_healthy()
    tok = Tokens(gate)
    samples: dict[str, list[float]] = {k: [] for k in ("baseline", "allow", "allow_amount", "deny_scope", "mint")}

    def expect(kind: str, status: int, body: dict, want: int) -> None:
        if status != want:
            raise SystemExit(f"{kind}: expected HTTP {want}, got {status}: {body.get('reason', body)}")

    # Day 10: a small payment goes through alone only against an open invoice, and paying it
    # closes it, so every timed payment gets its own invoice (created here, not timed).
    total = args.warmup + args.rounds
    bills: list[str] = []
    for _ in range(total):
        status, body, _ = gate.admin("POST", "/invoices", {"payee": "acct_acme_supplies", "amount": 40})
        expect("invoice setup", status, body, 201)
        bills.append(body["id"])

    print(f"AgentGate latency benchmark against {cfg.target} ({cfg.base_url}), "
          f"{args.rounds} rounds + {args.warmup} warm-up, slack={health.get('slack')}")
    for i in range(total):
        tok.fresh()
        keep = i >= args.warmup
        runs = [
            ("baseline", lambda: gate.request("GET", "/.well-known/jwks.json"), 200),
            ("allow", lambda: gate.tool(tok.mailer, "query_customers", {"limit": 1}), 200),
            ("allow_amount", lambda: gate.tool(tok.finance, "transfer_funds",
                                               {"amount": 40, "to_account": "acct_acme_supplies", "memo": "bench",
                                                "invoice_id": bills[i]}), 200),
            ("deny_scope", lambda: gate.tool(tok.mailer, "transfer_funds",
                                             {"amount": 40, "to_account": "ACCT-BENCH"}), 403),
        ]
        if i % 5 == 0:
            runs.append(("mint", lambda: gate.mint("mailer", ["query_customers", "send_email"],
                                                   "latency benchmark (mint)"), 201))
        for kind, fn, want in runs:
            status, body, elapsed = fn()
            expect(kind, status, body, want)
            if keep:
                samples[kind].append(elapsed)
        if (i + 1) % 50 == 0:
            print(f"  {i + 1}/{total}", flush=True)

    res = {k: stats(v) for k, v in samples.items() if v}
    base = res["baseline"]
    overhead = {k: {"p50": round(v["p50"] - base["p50"], 2), "p95": round(v["p95"] - base["p95"], 2)}
                for k, v in res.items() if k != "baseline"}

    print(f"\n{'path':13} {'n':>5} {'p50 ms':>8} {'p95 ms':>8} {'p99 ms':>8} {'+p50':>7} {'+p95':>7}")
    for k, v in res.items():
        o = overhead.get(k, {"p50": 0.0, "p95": 0.0})
        print(f"{k:13} {v['n']:>5} {v['p50']:>8.2f} {v['p95']:>8.2f} {v['p99']:>8.2f} "
              f"{o['p50']:>+7.2f} {o['p95']:>+7.2f}")
    a = overhead["allow"]
    print(f"\nGate overhead on an allowed tool call: +{a['p50']:.1f} ms p50, +{a['p95']:.1f} ms p95 "
          f"(vs an ungated request to the same server).")

    if not args.no_save:
        out_dir = REPO / "eval" / "results"
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = out_dir / f"latency-{cfg.target}-{stamp}.json"
        path.write_text(json.dumps({
            "target": cfg.target, "base_url": cfg.base_url,
            "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "client": f"{platform.system()} {platform.machine()} python {platform.python_version()}",
            "rounds": args.rounds, "warmup": args.warmup, "results_ms": res, "overhead_ms": overhead,
        }, indent=2), encoding="utf-8")
        print(f"Saved {path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
