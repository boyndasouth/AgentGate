# AgentGate audit anchors

This branch is written by a scheduled GitHub Action (`.github/workflows/anchor.yml` on `main`).
It has no code. `anchors.jsonl` holds one line per checkpoint of AgentGate's audit log:

| Field | Meaning |
| --- | --- |
| `last_id` | id of the newest audit row when the checkpoint was taken |
| `head_hash` | that row's hash; it covers every earlier row through the hash chain |
| `iat` | when the broker signed the checkpoint (Unix time) |
| `kid`, `jws` | the broker's Ed25519 signature over the three values above |
| `anchored_at` | when the Action wrote the line |

Why it exists: the audit log is a hash chain in a database. Someone who can write to that
database could edit a row and recompute every hash after it, and the chain would still verify.
They can't edit this branch. If a row that was anchored here later has a different hash, the
log was rewritten.

Check it yourself (no keys needed):

```
python scripts/anchor.py check --url https://agentgate-broker.onrender.com \
  --file https://raw.githubusercontent.com/boyndasouth/AgentGate/audit-anchors/anchors.jsonl
```

Never force-push or rewrite this branch: its value is that it only grows.
