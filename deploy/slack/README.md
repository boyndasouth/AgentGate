# Slack approvals setup (Day 4)

Escalated tool calls post an **Approve / Deny** message to one Slack channel. The waiting
agent polls `GET /approvals/{id}` every 2 s; a click resolves it; no click within
`APPROVAL_TTL_SECONDS` (default 120) counts as **deny**.

Use **two Slack apps**, one per mode. A Slack app is either in Socket Mode or HTTP mode,
and if your local broker and the Render broker shared one Socket Mode app, Slack would
split clicks between them at random.

| | Dev app (local Docker) | Prod app (Render) |
| --- | --- | --- |
| Manifest | `manifest.dev.yaml` | `manifest.prod.yaml` |
| How clicks arrive | Socket Mode: broker opens a websocket to Slack | HTTP: Slack POSTs to `https://<render-url>/slack/events` |
| Secrets | `SLACK_BOT_TOKEN` + `SLACK_APP_TOKEN` | `SLACK_BOT_TOKEN` + `SLACK_SIGNING_SECRET` |
| Where they go | `.env` | Render → Environment |

Only scope needed: `chat:write` (post, update, ephemeral replies).

## 1. Workspace and channel

1. Create a free workspace (slack.com/get-started) if you don't have one.
2. Create a channel, e.g. `#agentgate-approvals`.
3. Channel ID: open the channel → click its name → bottom of the **About** tab → `C0…`.
4. Your member ID: click your avatar → **Profile** → ⋮ → **Copy member ID** → `U0…`.

## 2. Dev app (local, Socket Mode)

1. api.slack.com/apps → **Create New App** → **From a manifest** → your workspace → paste `manifest.dev.yaml` → Create.
2. **Basic Information → App-Level Tokens → Generate Token and Scopes**: name `socket`, scope `connections:write` → copy `xapp-…`.
3. **Install App → Install to Workspace** → copy the **Bot User OAuth Token** `xoxb-…`.
4. In Slack, in the channel: `/invite @AgentGate Dev`.
5. Add to `.env` (PowerShell 5.1: never `>>`, it writes UTF-16):

```powershell
Add-Content -Encoding ascii .env @(
  'SLACK_BOT_TOKEN=xoxb-...',
  'SLACK_APP_TOKEN=xapp-...',
  'SLACK_APPROVALS_CHANNEL=C0XXXXXXX',
  'SLACK_APPROVERS=U0XXXXXXX=shiwin',
  'APPROVAL_TTL_SECONDS=120'
)
docker compose up -d --build broker
docker compose logs broker | Select-String 'Slack|AgentGate up'
```

You want `Slack approvals: Socket Mode connected` and `slack=socket`.

## 3. Done check (local)

```powershell
.\scripts\run_agents.ps1 big
```

1. The terminal prints `waiting for human approval …`.
2. Slack shows **Approval needed: transfer_funds** (agent finance, amount 5000, Northwind Consulting).
3. Click **Deny**. Within 2 s the terminal prints `approval …: deny (denied by user:shiwin via slack:U0…)`,
   then `finance says: …` explaining the refusal; the message in Slack changes to ❌ Denied by ….
4. `Invoke-RestMethod http://localhost:8000/audit/verify` → `valid: True`. The
   `approval_resolved` row has `approver = user:shiwin via slack:U0…`.

Also try: **Approve** (the broker runs the transfer and the agent reports the `tx_…` id),
no click (deny after 120 s; the message changes to ⌛ Expired), and a click from a Slack user
not in `SLACK_APPROVERS` (ephemeral "you aren't mapped" reply; nothing changes).

## 4. Prod app (Render, HTTP mode)

1. Edit `manifest.prod.yaml`: set `request_url` to `https://<your-service>.onrender.com/slack/events`.
2. Create the app from that manifest, install it, copy the **Bot User OAuth Token** and,
   under **Basic Information → App Credentials**, the **Signing Secret**.
3. `/invite @AgentGate` in the channel.
4. Render → `agentgate-broker` → **Environment**: add `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET`,
   `SLACK_APPROVALS_CHANNEL`, `SLACK_APPROVERS`. **Do not** set `SLACK_APP_TOKEN` on Render
   (it would switch the broker to Socket Mode). Save → redeploy.
5. `.\scripts\check_deploy.ps1` → health shows `"slack":"http"`.
6. `.\scripts\run_agents.ps1 -Target render big` → Deny in Slack.

## Fallback without Slack

Approvals work with Slack off (no `SLACK_BOT_TOKEN`): decide from a second terminal.

```powershell
.\scripts\decide.ps1                      # list pending approvals (local)
.\scripts\decide.ps1 -Id <uuid> -Deny     # or -Approve
.\scripts\decide.ps1 -Target render ...   # deployed broker
```

The same rules apply as for Slack clicks: OpenFGA must say `user:<approver>` is an
`approver` of the tool, and every decision is audited.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| Boot fails: `SLACK_BOT_TOKEN is set but missing: …` | Add the listed variables, or remove `SLACK_BOT_TOKEN` to run with Slack off. |
| Log `Slack post failed … not_in_channel` | `/invite` the bot into the channel. |
| `channel_not_found` | `SLACK_APPROVALS_CHANNEL` must be the ID (`C0…`), not `#name`. |
| `invalid_auth` / `not_authed` | Wrong or reinstalled bot token; copy the current `xoxb-…`. |
| Buttons show a ⚠️ / nothing happens (local) | Broker not connected: check the logs for `Socket Mode connected`; app-level token needs `connections:write`. |
| Buttons show a ⚠️ (Render) | Request URL wrong, `SLACK_SIGNING_SECRET` wrong, or the service was asleep. Warm it with `check_deploy.ps1` first. |
| Ephemeral "aren't mapped to an AgentGate user" | Add your member ID to `SLACK_APPROVERS`. |
| Ephemeral "not an approver of …" | That user has no `approver` tuple for the tool in `policy/tuples.yaml`. |
| Ephemeral "Not applied: already expired" | The 120 s window passed or the agent stopped waiting; rerun the scenario. |
