-- Day 6: read-only live feed for the admin UI.
-- Run once in the Supabase SQL editor (idempotent). Replace the placeholder
-- in the INSERT at the bottom with your Auth0 sub (shown on the UI's /denied page).
--
-- Model: the browser talks to Supabase with the admin's Auth0 ID token
-- (Third-Party Auth, role=authenticated). It may SELECT audit_events and
-- nothing else, and only if its `sub` is in public.ui_admins. All writes
-- (approve/deny, kill switch) go through the broker, never through Supabase.

-- 1. Allowlist of Auth0 subs. RLS on, no policies: invisible to anon/authenticated.
create table if not exists public.ui_admins (
    auth0_sub text primary key,          -- e.g. 'auth0|6745…' (not a uuid, so not auth.uid())
    email     text,
    added_at  timestamptz not null default now()
);
alter table public.ui_admins enable row level security;
revoke all on public.ui_admins from anon, authenticated;

-- 2. Policy helper. SECURITY DEFINER so it can read ui_admins despite RLS.
create or replace function public.is_ui_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1 from public.ui_admins a where a.auth0_sub = (auth.jwt() ->> 'sub')
    );
$$;
revoke all on function public.is_ui_admin() from public, anon;
grant execute on function public.is_ui_admin() to authenticated;

-- 3. Read-only: no API role may write to any broker table (the broker connects as postgres).
revoke insert, update, delete, truncate on
    public.agents, public.sessions, public.tokens, public.revocations, public.approvals, public.audit_events
from anon, authenticated;
revoke select on
    public.agents, public.sessions, public.tokens, public.revocations, public.approvals
from anon, authenticated;
revoke select on public.audit_events from anon;
grant select on public.audit_events to authenticated;

-- 4. Row-level read access to the audit log for listed admins only.
alter table public.audit_events enable row level security;
drop policy if exists "ui admins read audit" on public.audit_events;
create policy "ui admins read audit"
    on public.audit_events
    for select
    to authenticated
    using ((select public.is_ui_admin()));

-- 5. Stream inserts to Realtime (postgres_changes respects the policy above).
do $$
begin
    if not exists (
        select 1 from pg_publication_tables
        where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'audit_events'
    ) then
        alter publication supabase_realtime add table public.audit_events;
    end if;
end $$;

-- 6. You. Replace the placeholder, then run.
insert into public.ui_admins (auth0_sub, email)
values ('auth0|6afa1e1ed3444608d2161afa', 'shiwinfdo05@gmail.com')
on conflict (auth0_sub) do nothing;

-- Check:
--   select * from public.ui_admins;
--   select tablename from pg_publication_tables where pubname = 'supabase_realtime';
