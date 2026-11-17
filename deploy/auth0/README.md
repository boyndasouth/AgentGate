# Auth0 setup for agent login (Day 13)

An agent that logs in as itself is an Auth0 **Machine to Machine** application. It gets an Auth0
access token with the client credentials grant and trades it at `POST /tokens/agent` for a
normal 10-minute AgentGate token. The broker only needs to know your tenant and the API's
identifier; it never sees a client secret.

Menu names below are from the Auth0 dashboard in November 2026; they move around now and then.

## 1. Create the API (once)

Applications → APIs → **Create API**

| Field | Value |
| --- | --- |
| Name | `AgentGate API` |
| Identifier | `https://agentgate-broker.onrender.com` (any URI works; it is only a name, Auth0 never calls it. It can't be changed later) |
| JSON Web Token (JWT) Profile | `Auth0` (the default). Not `RFC 9068`: that profile has no `gty` / `azp` claims and the broker refuses it |
| Signing Algorithm | `RS256` (the default). The broker refuses HS256 and PS256 |

No permissions (scopes) are needed: what an agent may do is decided by its grants in AgentGate,
not by Auth0.

Optional, in the API's Settings: **Token Expiration**. The default is 86,400 s (24 h). A shorter
lifetime limits how long a stolen Auth0 token can be used to log in, and costs more tokens
from the monthly quota (see below). If you change it, you can also set
`AUTH0_MAX_TOKEN_AGE_SECONDS` on the broker to the same number.

## 2. Tell the broker (once)

Render → agentgate-broker → Environment:

| Variable | Value |
| --- | --- |
| `AUTH0_DOMAIN` | your tenant domain, e.g. `dev-abc123.us.auth0.com` (same tenant as the admin UI; it is the host in the UI's `AUTH_AUTH0_ISSUER`) |
| `AUTH0_AUDIENCE` | the API Identifier from step 1, character for character |

Saving redeploys. The deploy log then says
`agent login: auth0, issuer https://<domain>/, audience <identifier>`, and `GET /health`
reports `"agent_login": "auth0"`. Without the two variables it says `off` and
`POST /tokens/agent` answers 503; nothing else changes.

A variable that is set but unusable (an audience without a domain, a domain that is not a
host name) stops the boot with a message naming it. Render keeps the previous deploy running.

## 3. One M2M application per agent

Applications → Applications → **Create Application** → **Machine to Machine Applications**
→ authorize it for `AgentGate API` (no permissions to tick).

From its Settings tab, copy:

- **Client ID**: goes on the agent in AgentGate (admin UI → Agents → Login, or
  `PATCH /agents/{id}` with `{"auth0_client_id": "..."}`). It is not a secret.
- **Client Secret**: goes to the agent only (its `.env.agent`, a secret store). AgentGate
  never needs it.

One client maps to one agent. Once an agent has a client id, the orchestrator key can no longer
mint tokens for it, and the tokens it held before are revoked.

Creating the API also creates an application called `AgentGate API (Test Application)`. You
can use that one for the first agent.

## 4. Try it

`.env.agent` in the repo root (ignored by git):

```
AUTH0_DOMAIN=dev-abc123.us.auth0.com
AUTH0_CLIENT_ID=...
AUTH0_CLIENT_SECRET=...
AUTH0_AUDIENCE=https://agentgate-broker.onrender.com
AGENTGATE_URL=https://agentgate-broker.onrender.com
```

```powershell
docker run --rm -v "${PWD}:/w" -w /w python:3.12-slim python examples/agent_login.py --env-file .env.agent --tool query_customers
```

(Plain `py examples\agent_login.py ...` works too if your Windows Python can reach Render; on
Day 12 it couldn't.)

## The token quota

Auth0's Free plan includes about 1,000 M2M tokens a month for the whole tenant. Every call to
`https://<domain>/oauth/token` counts, including the **Test** tab of the API in the dashboard.
Calls to AgentGate's `/tokens/agent` don't: one Auth0 token can be used to log in as often as
you like until it expires.

So an agent must keep its Auth0 token and reuse it. `examples/agent_login.py` caches it in
`.agentgate-token-cache.json`; with the default 24 h lifetime that is about 30 tokens a month
per agent. A loop that asks Auth0 for a new token on every run would use up the month in an
afternoon. When the quota is used up, Auth0 refuses new tokens until the next month and agents
can't log in; tokens already issued keep working until they expire.

The local tests never touch Auth0: compose runs a mock issuer (`deploy/mock-issuer/server.py`).

## Things that make the broker refuse a real Auth0 token

| Reason in the response | Cause |
| --- | --- |
| `token was issued for another audience` | The agent asked Auth0 for a different `audience`, or `AUTH0_AUDIENCE` on the broker differs from the API Identifier (a trailing slash counts) |
| `token is from another issuer` | `AUTH0_DOMAIN` names a different tenant (or a custom domain the tokens don't use) |
| `only RS256 tokens ... are accepted` | The API's signing algorithm is HS256 or PS256 |
| `not a machine-to-machine (client credentials) token` | A user's access token; or the API uses the RFC 9068 profile; or "agent subject claims" are enabled on the API (then `sub` loses its `@clients` suffix) |
| `Auth0 client ... is not mapped to an agent` | The Client ID isn't set on any agent in AgentGate |
| `token is older than ... s` | The API's token lifetime is longer than `AUTH0_MAX_TOKEN_AGE_SECONDS` |
