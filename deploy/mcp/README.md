# The MCP gateway (`/mcp`)

Any MCP client can use AgentGate as an MCP server. It connects to `https://<broker>/mcp`, sees
**only the tools its agent may use**, and every call goes through the same gate as
`POST /tools/{name}`: same policy, same audit rows, same taint rules, same Slack approvals.

## How a client connects

The client sends its agent's **Auth0 machine-to-machine access token** as the bearer token on every
request (the same token `POST /tokens/agent` takes). The broker verifies it, maps the Auth0 client
to an agent (`auth0_client_id`), and mints its own short-lived AgentGate token for that agent per MCP
session, renewing it before it expires. The client never holds an AgentGate token.

| Situation | Answer |
|---|---|
| no / forged token | 401 (`WWW-Authenticate: Bearer`); a forged token is logged, not audited |
| genuine token, wrong audience / expired | 401, audited ("MCP login: ...") |
| Auth0 client mapped to no agent | 403, audited |
| identity provider not configured | 503 |
| request for protocol `2026-07-28` (sessionless) | 400 / JSON-RPC `-32022` listing the supported versions; auto-negotiating clients fall back |

Only the handshake-era protocol versions (with an `Mcp-Session-Id`) are served. A session belongs to
the agent that opened it: another agent presenting its session id is refused.

## What the agent sees and what happens on a call

- `tools/list` returns the registry tools the agent may hold (the rule used when issuing a token:
  enabled, valid, and reachable under the policy). Other tools are not listed.
- `tools/call` accepts any name and judges it with the gate. A call to a tool the agent was never
  shown is denied and audited like any other.
- **Escalation blocks.** A call that needs a human stays open while the approval is pending (Slack
  or the admin API), with a progress notification about every 5 s, until the approval TTL
  (`APPROVAL_TTL_SECONDS`, default 120). Approve returns the tool's result; Deny or timeout returns an
  error result. If the client cancels or disconnects, the approval is closed (counts as deny), so a
  late click can't run a call nobody is waiting for. At most 16 calls wait at once; more are refused.
- Results: an allowed call returns the tool's result as text (and structured content when it is
  an object). Denials and failed tools are MCP error results (`isError`) whose text says why and
  names the audit row. The agent's arguments are never echoed back.

## Connecting

Get a token (a real Auth0 M2M application; `examples/agent_login.py` does the same):

```powershell
$body = @{ grant_type = 'client_credentials'; client_id = $env:AUTH0_CLIENT_ID
           client_secret = $env:AUTH0_CLIENT_SECRET; audience = $env:AUTH0_AUDIENCE } | ConvertTo-Json
$token = (Invoke-RestMethod -Method Post -Uri "https://$env:AUTH0_DOMAIN/oauth/token" `
          -ContentType 'application/json' -Body $body).access_token
```

**MCP Inspector:** `npx @modelcontextprotocol/inspector`, transport *Streamable HTTP*, URL
`https://<broker>/mcp` (locally `http://localhost:8000/mcp`), add the header
`Authorization: Bearer <token>`.

**Claude Desktop:** its built-in connectors expect OAuth, which this gateway does not offer.
Bridge a static header with `mcp-remote` in `claude_desktop_config.json`:

```json
{ "mcpServers": { "agentgate": {
    "command": "npx",
    "args": ["-y", "mcp-remote", "https://<broker>/mcp", "--header", "Authorization:${AUTH_HEADER}"],
    "env": { "AUTH_HEADER": "Bearer <token>" } } } }
```

The token in that file expires when the Auth0 token does (24 h by default): regenerate it then.

> Neither client has been run against this gateway yet (see PROGRESS.md); the automated test uses the
> MCP Python SDK client. Locally, the mock issuer is not published to the host; to get a token for
> a manual run use your real Auth0 tenant (`AUTH0_ISSUER`, `AUTH0_JWKS_URL`, `AUTH0_AUDIENCE` in `.env`).

## Putting a remote MCP server behind the gate

Registry tools can forward to a remote MCP server (`upstream.kind = "mcp"`). The credential is an
env var named by `credential_ref` (`UPSTREAM_*`), as for http tools; the agent never sees it.

```powershell
$h = @{ 'X-Admin-Key' = $env:AGENTGATE_ADMIN_KEY }
$body = @{ prefix = 'gh'; url = 'https://mcp.example.com/mcp'; credential_ref = 'UPSTREAM_GH_TOKEN' } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "$env:AGENTGATE_URL/mcp-upstreams/import" -Headers $h -ContentType 'application/json' -Body $body
```

Imported tools are named `<prefix>.<remote name>` and arrive **disabled, risk class `destructive`,
tainting, with no `context_map` and no grants**. Nothing can call them until an admin reviews each
one (`PATCH /tools/{name}`: `risk_class`, `context_map`, `enabled`) and grants it to an agent. A tool
whose schema the gate can't fully understand is skipped, with the reason. Re-importing never
overwrites an existing row.

The remote connection is as strict as an http upstream: https only (or a host in
`UPSTREAM_PRIVATE_HOSTS`), an address resolved once and required to be public, no redirects, a size
cap, the credential scrubbed from what comes back, and text from the remote server never copied
into error messages. Every call is its own short MCP session.
