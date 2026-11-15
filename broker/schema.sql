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
    event_type      text NOT NULL,               -- 'tool_call' | 'token_issued' | 'token_denied' | 'token_revoked' | 'agent_disabled' | 'agent_enabled' | 'approval_resolved' | 'approval_refused' | 'session_tainted'
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
