-- Run ONCE in Supabase -> SQL Editor, after the broker has started (it creates the tables).
-- Supabase exposes the public schema through its REST API using the anon key.
-- With RLS on and no policies, anon/authenticated can read and write NOTHING.
-- The broker connects as the postgres role, which bypasses RLS, so it is unaffected.
-- Day 6 adds a read-only SELECT policy for the admin UI's Realtime feed.
ALTER TABLE agents       ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions     ENABLE ROW LEVEL SECURITY;
ALTER TABLE tokens       ENABLE ROW LEVEL SECURITY;
ALTER TABLE revocations  ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals    ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;

-- Check: every row should say true.
SELECT relname, relrowsecurity FROM pg_class
WHERE relname IN ('agents','sessions','tokens','revocations','approvals','audit_events');
