-- AgentGate broker schema. Idempotent: the broker runs this at startup.
-- Same SQL works on local Postgres (Day 2) and Supabase (Day 3).

-- Agent registry: every agent is a real identity with a human owner.
CREATE TABLE IF NOT EXISTS agents (
    id           text PRIMARY KEY,               -- 'researcher', 'mailer', 'finance'
    owner        text NOT NULL,                  -- 'user:shiwin' (mirrors the OpenFGA owner tuple)
    display_name text NOT NULL,
    status       text NOT NULL DEFAULT 'active'  -- 'active' | 'disabled' (kill switch)
                 CHECK (status IN ('active', 'disabled')),
    created_at   timestamptz NOT NULL DEFAULT now()
);

INSERT INTO agents (id, owner, display_name) VALUES
    ('researcher', 'user:shiwin', 'Researcher'),
    ('mailer',     'user:shiwin', 'Mailer'),
    ('finance',    'user:shiwin', 'Finance')
ON CONFLICT (id) DO NOTHING;

-- One session = one orchestrator run, shared by every agent in that run.
-- tainted is set by the gate (Day 5), never by an agent.
CREATE TABLE IF NOT EXISTS sessions (
    id         uuid PRIMARY KEY,
    tainted    boolean NOT NULL DEFAULT false,
    tainted_by text,                             -- tool that tainted it, e.g. 'read_web'
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Every issued token, so the admin UI can list live credentials.
CREATE TABLE IF NOT EXISTS tokens (
    jti        uuid PRIMARY KEY,
    agent_id   text NOT NULL REFERENCES agents(id),
    session_id uuid NOT NULL REFERENCES sessions(id),
    task_id    uuid NOT NULL,
    task       text NOT NULL,
    scopes     text[] NOT NULL,
    issued_at  timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);

-- Revocations. A row with jti kills one token; a row with agent_id
-- (kill switch) kills every token that agent was issued before revoked_at.
CREATE TABLE IF NOT EXISTS revocations (
    id         bigserial PRIMARY KEY,
    jti        uuid,
    agent_id   text REFERENCES agents(id),
    reason     text NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT now(),
    CHECK (jti IS NOT NULL OR agent_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS revocations_jti_idx   ON revocations (jti);
CREATE INDEX IF NOT EXISTS revocations_agent_idx ON revocations (agent_id, revoked_at);

-- Escalated calls waiting for a human. Day 2 only inserts 'pending' rows;
-- Day 4 adds the Slack buttons that resolve them.
CREATE TABLE IF NOT EXISTS approvals (
    id          uuid PRIMARY KEY,
    agent_id    text NOT NULL REFERENCES agents(id),
    session_id  uuid NOT NULL REFERENCES sessions(id),
    task_id     uuid NOT NULL,
    tool        text NOT NULL,
    args        jsonb NOT NULL,                  -- needed to replay the call once approved
    args_hash   text NOT NULL,
    reason      text NOT NULL,
    status      text NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    approver    text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz
);

-- Day 4: Slack approvals. ALTERs (not a new CREATE) so an existing Supabase table upgrades in place.
-- args is kept only while pending (the broker replays the call on Approve), then set to NULL.
ALTER TABLE approvals ALTER COLUMN args DROP NOT NULL;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS expires_at      timestamptz;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS session_tainted boolean;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS result          jsonb;   -- tool output after Approve, for the polling agent
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS resolved_via    text;    -- 'slack:U0123' | 'admin-api' | 'timeout' | 'agent-cancel'
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS slack_channel   text;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS slack_ts        text;    -- message to update after a decision
UPDATE approvals SET expires_at = created_at + interval '2 minutes' WHERE expires_at IS NULL;
ALTER TABLE approvals ALTER COLUMN expires_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS approvals_status_idx ON approvals (status, created_at);

-- Day 5: when the session became tainted (tainted_by already exists).
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS tainted_at timestamptz;

-- Append-only, hash-chained audit log.
-- hash = sha256(prev_hash || canonical_json(event)). Args are stored as a keyed hash only.
CREATE TABLE IF NOT EXISTS audit_events (
    id              bigint PRIMARY KEY,          -- assigned by the broker, gap-free
    ts              text NOT NULL,               -- canonical UTC string, hashed as-is
    event_type      text NOT NULL,               -- 'tool_call' | 'token_issued' | 'token_denied' | 'token_revoked' | 'agent_disabled' | 'agent_enabled' | 'approval_resolved' | 'approval_refused' | 'session_tainted' | 'registry_changed' | ...
    agent_id        text,
    session_id      text,
    task_id         text,
    jti             text,
    tool            text,
    args_hash       text,
    decision        text NOT NULL,               -- 'allow' | 'escalate' | 'deny' | 'info'
    reason          text NOT NULL,
    approver        text,
    session_tainted boolean,
    prev_hash       text NOT NULL,
    hash            text NOT NULL
);

-- Day 10 (closes G05): the accounts-payable system's invoices (a mock of it). Finance may pay a
-- small amount ALONE only against an open invoice from that payee for exactly that amount;
-- paying it marks it paid, so paying the same invoice twice goes to a human. Invoices are
-- created by an admin (POST /invoices), never by an agent or the orchestrator.
CREATE TABLE IF NOT EXISTS invoices (
    id          text PRIMARY KEY,
    payee       text NOT NULL,
    amount      numeric(12, 2) NOT NULL CHECK (amount > 0),
    status      text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'paid')),
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    paid_at     timestamptz,
    paid_tx     text
);
INSERT INTO invoices (id, payee, amount, created_by)
VALUES ('INV-1042', 'acct_acme_supplies', 40.00, 'seed') ON CONFLICT (id) DO NOTHING;

-- Day 10: delegation chains. Agent A grants agent B part of its access for a while; B trades
-- its own token for one that acts on A's behalf (RFC 8693-style token exchange). The OpenFGA
-- tuples are the grant; this table is the record the gate checks for revocation and depth.
CREATE TABLE IF NOT EXISTS delegations (
    id              uuid PRIMARY KEY,
    principal       text NOT NULL REFERENCES agents(id),   -- whose access is being used (the root)
    delegator       text NOT NULL REFERENCES agents(id),   -- who granted this hop
    delegate        text NOT NULL REFERENCES agents(id),   -- who receives it
    tools           text[] NOT NULL,
    parent_id       uuid REFERENCES delegations(id),       -- hop 2 points at hop 1
    depth           int NOT NULL CHECK (depth BETWEEN 1 AND 2),
    origin_session  uuid NOT NULL REFERENCES sessions(id),  -- delegator's session: its taint follows the grant
    created_jti     uuid NOT NULL,                          -- token that created it
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    revoked_reason  text
);
CREATE INDEX IF NOT EXISTS delegations_parent_idx ON delegations (parent_id);
CREATE INDEX IF NOT EXISTS delegations_agents_idx ON delegations (delegator, delegate);

-- Tokens minted by exchange: the agent calling (agent_id) acts for `principal` via these delegations.
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS principal      text;
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS delegation_ids uuid[];
-- A delegated call that escalates: Approve checks the whole chain again (kill switch, revocation).
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS principal      text;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS delegation_ids uuid[];

-- Day 11: the tool registry. A tool is a row, not Python code: what its arguments look like,
-- how risky it is, which arguments the policy looks at, and where the call goes.
-- Safe defaults: a new row taints the session and is DISABLED until someone turns it on.
CREATE TABLE IF NOT EXISTS tools (
    name            text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9_.]{1,63}$'),
    description     text NOT NULL DEFAULT '',
    args_schema     jsonb NOT NULL,                  -- JSON Schema 2020-12; unknown arguments are always refused
    risk_class      text NOT NULL CHECK (risk_class IN ('read', 'write', 'egress', 'money', 'destructive')),
    context_map     jsonb NOT NULL DEFAULT '{}',     -- policy input -> argument name: amount, url, recipient, payee, invoice
    taints_session  boolean NOT NULL DEFAULT true,   -- returns outside content; the session is tainted after a call
    upstream        jsonb NOT NULL,                  -- {"kind": "builtin" | "http" | "mcp", ...}; http since Day 12, mcp later
    credential_ref  text,                            -- NAME of an env var (UPSTREAM_...) holding the upstream credential, never the secret
    enabled         boolean NOT NULL DEFAULT false,
    version         integer NOT NULL DEFAULT 1,      -- bumped by the trigger on every real change
    created_by      text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- One row, one number: bumped whenever `tools` changes, so the broker can tell with a single
-- primary-key read that its cached registry is stale (also after an edit made directly in SQL).
CREATE TABLE IF NOT EXISTS registry_state (
    id      boolean PRIMARY KEY DEFAULT true CHECK (id),
    version bigint NOT NULL DEFAULT 1
);
INSERT INTO registry_state (id) VALUES (true) ON CONFLICT (id) DO NOTHING;

CREATE OR REPLACE FUNCTION agentgate_tool_row_changed() RETURNS trigger
LANGUAGE plpgsql SET search_path = '' AS $fn$
BEGIN
    IF to_jsonb(NEW) - 'version' - 'updated_at' IS DISTINCT FROM to_jsonb(OLD) - 'version' - 'updated_at' THEN
        NEW.version := OLD.version + 1;
        NEW.updated_at := now();
    ELSE
        NEW.version := OLD.version;
    END IF;
    RETURN NEW;
END
$fn$;

CREATE OR REPLACE FUNCTION agentgate_registry_bump() RETURNS trigger
LANGUAGE plpgsql SET search_path = '' AS $fn$
BEGIN
    UPDATE public.registry_state SET version = version + 1;
    RETURN NULL;
END
$fn$;

CREATE OR REPLACE TRIGGER tools_row_changed BEFORE UPDATE ON tools
    FOR EACH ROW EXECUTE FUNCTION agentgate_tool_row_changed();
CREATE OR REPLACE TRIGGER tools_registry_bump AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON tools
    FOR EACH STATEMENT EXECUTE FUNCTION agentgate_registry_bump();

-- The five demo tools, now ordinary registry rows. Their mock code stays in tools.py as
-- built-in handlers. ON CONFLICT DO NOTHING: a row edited later is never overwritten at boot.
INSERT INTO tools (name, description, args_schema, risk_class, context_map, taints_session, upstream, enabled, created_by)
VALUES
    ('read_web', 'Fetch a web page (mock).',
     '{"type": "object", "required": ["url"], "additionalProperties": false,
       "properties": {"url": {"type": "string", "maxLength": 2048}}}',
     'read', '{"url": "url"}', true, '{"kind": "builtin"}', true, 'seed'),
    ('read_inbox', 'Read the latest inbox messages (mock).',
     '{"type": "object", "additionalProperties": false,
       "properties": {"limit": {"type": "integer", "default": 5}}}',
     'read', '{}', true, '{"kind": "builtin"}', true, 'seed'),
    ('send_email', 'Send an email (mock).',
     '{"type": "object", "required": ["to", "subject", "body"], "additionalProperties": false,
       "properties": {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}}}',
     'egress', '{"recipient": "to"}', false, '{"kind": "builtin"}', true, 'seed'),
    ('transfer_funds', 'Move money to an account (mock).',
     '{"type": "object", "required": ["amount", "to_account"], "additionalProperties": false,
       "properties": {"amount": {"type": "number"}, "to_account": {"type": "string"},
                      "memo": {"type": "string", "default": ""}, "invoice_id": {"type": "string", "default": ""}}}',
     'money', '{"amount": "amount", "payee": "to_account", "invoice": "invoice_id"}', false,
     '{"kind": "builtin"}', true, 'seed'),
    ('query_customers', 'List customers from the CRM (mock).',
     '{"type": "object", "additionalProperties": false,
       "properties": {"limit": {"type": "integer", "default": 10}}}',
     'read', '{}', false, '{"kind": "builtin"}', true, 'seed')
ON CONFLICT (name) DO NOTHING;

-- Day 12: agents, grants and approvers can be made through the admin API, not only seed files.
-- OpenFGA holds the tuples the gate checks; these tables are the record of what the API wrote,
-- so that (a) the boot-time sync in deploy/render/seed_fga.py keeps them (it makes the store
-- equal to policy/tuples.yaml PLUS these rows) and (b) the broker can write them again into a
-- fresh store. A grant that is in OpenFGA but not here comes from policy/tuples.yaml and can
-- only be changed there.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS created_by text NOT NULL DEFAULT 'seed';

CREATE TABLE IF NOT EXISTS grants (
    agent_id    text NOT NULL REFERENCES agents(id),
    tool        text NOT NULL,                   -- no FK: a tool row removed in SQL leaves a dead, harmless grant
    relation    text NOT NULL CHECK (relation IN ('direct_invoker', 'approval_invoker')),
    mode        text NOT NULL,                   -- direct | direct_if_untainted | direct_allowlisted_recipient | ... | approval
    params      jsonb NOT NULL DEFAULT '{}',     -- the mode's allowlist / limit, as given to the API
    fga_tuple   jsonb NOT NULL,                  -- the OpenFGA tuple key exactly as written
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, tool, relation)       -- OpenFGA holds one tuple per (user, relation, object)
);

CREATE TABLE IF NOT EXISTS tool_approvers (
    tool        text NOT NULL,
    user_id     text NOT NULL,                   -- 'user:shiwin'
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tool, user_id)
);

-- Supabase exposes `public` through its REST API; the broker connects as postgres and bypasses RLS.
-- (The six Day 3 tables are covered by deploy/supabase_rls.sql; new tables enable it here.)
ALTER TABLE invoices    ENABLE ROW LEVEL SECURITY;
ALTER TABLE delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE tools          ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE grants         ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_approvers ENABLE ROW LEVEL SECURITY;
