# DECISIONS

One line per choice and its reason.

- 2026-11-14 — Everything local runs in Docker Compose — avoids Windows native-install friction.
- 2026-11-14 — Repo lives outside OneDrive (e.g. C:\dev\agentgate) — OneDrive sync locks files and breaks bind mounts / node_modules.
- 2026-11-14 — Two Postgres containers: one for OpenFGA, one for the broker — OpenFGA owns its schema/migrations; broker DB maps 1:1 to Supabase later.
- 2026-11-14 — Broker Postgres on host port 5433 — avoids clashing with any locally installed Postgres on 5432.
- 2026-11-14 — Named Docker volumes, not bind mounts, for DB data — faster and immune to OneDrive/Windows path issues.
- 2026-11-14 — OpenFGA image on `latest` for Day 0, pin a version once Day 1 tests pass — reproducible deploys on Render.
- 2026-11-14 — Playground enabled locally only; disable on Render (Day 3) — the docs say not for production.
