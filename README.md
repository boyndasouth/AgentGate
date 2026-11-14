# AgentGate

Identity & permissions broker for AI agents: short-lived scoped credentials,
relationship-based authorization (OpenFGA), human approval for risky actions
(Slack), session taint tracking against prompt injection, and a hash-chained
audit log.

> Work in progress — one-week build. See `PROGRESS.md` for status.

## Repo layout

```
agentgate/
├── broker/            # Litestar API: tokens, tool gateway, decision engine, audit log   (Day 2)
├── agents/            # Pydantic AI demo agents + orchestrator                           (Day 3)
├── ui/                # SvelteKit admin UI (Auth0, Supabase Realtime)                    (Day 6)
├── policy/
│   ├── model.fga      # OpenFGA authorization model
│   └── tests.fga.yaml # model tests                                                     (Day 1)
├── db/init/           # schema.sql goes here; runs on first start of a fresh broker DB   (Day 2)
├── scripts/           # check-stack.ps1 / .sh, seed + demo scripts
├── docker-compose.yml
└── .env.example
```

## Quickstart (Windows, PowerShell)

Prereqs: Docker Desktop (WSL 2 backend), Git.

> **Clone outside OneDrive** (e.g. `C:\dev\agentgate`). OneDrive sync locks
> files and fights with Docker bind mounts and `node_modules`.

```powershell
git clone <your-repo-url> C:\dev\agentgate
cd C:\dev\agentgate
Copy-Item .env.example .env
docker compose up -d
docker compose ps            # fga-migrate should show "exited (0)", the rest "healthy"
.\scripts\check-stack.ps1    # Day 0 done check
start http://localhost:3000/playground
```

| Service | URL |
| --- | --- |
| OpenFGA HTTP API | http://localhost:8080 |
| OpenFGA Playground | http://localhost:3000/playground |
| Broker Postgres | `postgresql://agentgate:agentgate@localhost:5433/agentgate` |

Useful commands:

```powershell
docker compose logs -f openfga     # follow OpenFGA logs
docker compose down                # stop (keeps data)
docker compose down -v             # stop and wipe both databases
```

To try the model in the Playground: create a store, open the model editor,
and paste in `policy/model.fga`.
