# AgentGate admin UI

SvelteKit 2 (Svelte 5) app behind Auth0 login, deployed on Vercel. It shows the
agents and their grants with a kill switch each, the approvals queue (same queue
as Slack), a live decision feed and a **Verify chain** button. A demo runner
replays the demo beats as scripted gate calls, with no LLM.

```
browser ──(Auth.js session cookie)──► SvelteKit server routes ──(admin / orchestrator key)──► broker (Render)
   │
   └──(Auth0 ID token, role=authenticated)──► Supabase Realtime: SELECT audit_events only, RLS: ui_admins
```

- **Writes go through the broker only.** Approve/Deny, the kill switch and verify are server routes holding `AGENTGATE_ADMIN_KEY`. The browser never sees it.
- **The approver comes from the session.** Auth0 user → `APPROVERS` → `user:<name>`, and the broker still asks OpenFGA whether that user is an approver on the tool.
- **The live feed is read-only.** Supabase Third-Party Auth accepts the Auth0 ID token. RLS lets only subs in `public.ui_admins` read `audit_events`, and nothing else. If Realtime isn't configured or fails, the feed polls `GET /audit/events` every 3 s.

## 1. Auth0 (about 10 min)

1. **Applications → Create Application → Regular Web Application**, named "AgentGate Admin".
2. In its **Settings** tab:
   - Allowed Callback URLs: `http://localhost:5173/auth/callback/auth0, https://YOUR-APP.vercel.app/auth/callback/auth0`
   - Allowed Logout URLs and Allowed Web Origins: `http://localhost:5173, https://YOUR-APP.vercel.app`
   - Copy the **Domain**, **Client ID** and **Client Secret**.
3. **Authentication → Database → Username-Password-Authentication**: turn on **Disable Sign Ups**. Then go to **User Management → Users → Create User** and create your own login.
4. **Actions → Library → Create Action → Build from scratch**, named "Supabase role", trigger *Login / Post Login*:
   ```js
   exports.onExecutePostLogin = async (event, api) => {
     api.idToken.setCustomClaim('role', 'authenticated');
   };
   ```
   **Deploy** it, then open **Actions → Triggers → post-login**, drag it into the flow and click **Apply**. Auth0 strips this claim from access tokens, which is why the UI sends Supabase the ID token. Auth0 moves these menus around occasionally, so if one isn't where described, search the dashboard for "Triggers".

## 2. Supabase (about 5 min)

1. **Authentication → Sign In / Providers → Third-Party Auth → Add provider → Auth0**. Tenant ID is the first part of your Auth0 domain (`dev-abc123` in `dev-abc123.us.auth0.com`), and the region is `us`.
2. Sign in to the UI once. The `/denied` page shows your **Auth0 sub**.
3. In the SQL editor, put that sub into `deploy/supabase_ui.sql` and run it.
4. **Project Settings → API**: copy the project URL and the anon (publishable) key into `PUBLIC_SUPABASE_URL` / `PUBLIC_SUPABASE_ANON_KEY`.

## 3. Run locally (PowerShell)

```powershell
winget install OpenJS.NodeJS.LTS   # once; open a new terminal afterwards
cd C:\Users\shiwi\agentgate\ui
npm ci
Copy-Item .env.example .env        # then fill it in
# AUTH_SECRET:
$b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b)
npm run dev                        # http://localhost:5173
```

The local broker writes to local Postgres, not Supabase, so locally the feed shows "polling". Set `BROKER_URL` to the Render broker to see Realtime.

## 4. Deploy to Vercel

1. **Add New → Project → import `boyndasouth/AgentGate`**, set **Root Directory: `ui`** (Vercel detects SvelteKit).
2. Add every variable from `.env.example` with production values: the Render broker URL plus the **prod** admin and orchestrator keys from `.env.render`, and a fresh `AUTH_SECRET`.
3. Deploy, then add the real `https://….vercel.app` URL to the Auth0 callback, logout and origin lists.

## Tests

```powershell
python tests/mock_broker.py 8765   # terminal 1
node tests/smoke.mjs               # terminal 2: runs every demo beat against the mock
npm run check                      # svelte-check + types
```
