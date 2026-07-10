-- ============================================================
-- SHE RISES — DATABASE SCHEMA (Supabase / Postgres)
-- ============================================================
-- Design notes:
--   - profiles.id references Supabase's built-in auth.users, so
--     real login (email/password or magic link) replaces the
--     current name-picker prototype.
--   - Row Level Security (RLS) is what actually enforces "a
--     counsellor only sees their own assigned cases" — this is
--     NOT optional for a platform holding domestic violence /
--     self-harm disclosures. It must be enabled on every table
--     that holds sensitive data.
--   - Tags are kept as a simple text[] array on `cases` and
--     `media` for now (fast to build, fine at this scale).
--     If reporting needs grow later (e.g. "trend of DV cases by
--     month"), these can be normalized into a `tags` lookup
--     table + join table without breaking the app.
-- ============================================================

-- ---------- ENUMS ----------
create type user_role as enum ('volunteer', 'counsellor', 'admin', 'media_manager');
create type case_status as enum ('new', 'triaged', 'assigned', 'in_progress', 'resolved', 'closed');
create type case_severity as enum ('standard', 'high', 'crisis');
create type case_source as enum ('whatsapp_bot', 'manual', 'web_form');
create type media_type as enum ('podcast', 'article', 'reel');

-- ---------- PROFILES ----------
-- One row per team member (volunteer / counsellor / admin / media manager).
-- id matches the Supabase auth.users id, so RLS can use auth.uid() directly.
create table profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  full_name text not null,
  role user_role not null default 'volunteer',
  is_active boolean not null default true,

  -- public-facing fields, only shown on /find-a-counsellor when is_public_listed = true
  is_public_listed boolean not null default false,
  credential text,               -- e.g. "Clinical Psychologist"
  public_bio text,
  location text,                 -- e.g. "Mumbai" or "Online only"
  languages text,                -- e.g. "English, Gujarati"
  specialties text[] default '{}',  -- e.g. {'Depression','Grief'}

  created_at timestamptz not null default now()
);

-- ---------- CASES ----------
create table cases (
  id uuid primary key default gen_random_uuid(),
  case_ref text not null unique,      -- human-readable, e.g. 'SR-1042'
  alias text not null,                -- non-identifying reference, e.g. "Caller, initials S.A."
  note text not null,                 -- what they shared, as summarized by the volunteer

  source case_source not null default 'manual',
  status case_status not null default 'new',
  severity case_severity not null default 'standard',
  tags text[] not null default '{}', -- e.g. {'Depression','Anxiety'}

  assigned_to uuid references profiles(id),   -- the counsellor, null until triaged
  created_by uuid references profiles(id),    -- the volunteer who logged/triaged it

  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  resolved_at timestamptz
);

-- ---------- CASE UPDATES (timeline / session notes) ----------
create table case_updates (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references cases(id) on delete cascade,
  author_id uuid references profiles(id),
  note text not null,
  created_at timestamptz not null default now()
);

-- ---------- CRISIS ALERT LOG ----------
-- Audit trail proving crisis-tagged cases were actually seen fast —
-- important for accountability once the auto-escalation protocol exists.
create table crisis_alerts (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references cases(id) on delete cascade,
  triggered_at timestamptz not null default now(),
  notified_user_id uuid references profiles(id),
  acknowledged_at timestamptz
);

-- ---------- MEDIA (Voices library) ----------
create table media (
  id uuid primary key default gen_random_uuid(),
  type media_type not null,
  tag text not null,
  title text not null,
  teaser text not null,
  url text not null,
  gradient_start text default '#E3A9BE',
  gradient_end text default '#E3C68C',
  published boolean not null default true,
  created_by uuid references profiles(id),
  created_at timestamptz not null default now()
);

-- ============================================================
-- ROW LEVEL SECURITY
-- ============================================================
alter table profiles enable row level security;
alter table cases enable row level security;
alter table case_updates enable row level security;
alter table crisis_alerts enable row level security;
alter table media enable row level security;

-- Helper: read the caller's role from their profile row
create or replace function current_role_name() returns user_role as $$
  select role from profiles where id = auth.uid();
$$ language sql stable security definer;

-- ---------- profiles ----------
-- Anyone signed in can see their own profile row.
create policy "own profile" on profiles
  for select using (id = auth.uid());
-- Public directory: anyone (including anonymous website visitors) can see
-- listed counsellors — this powers the public /find-a-counsellor page.
create policy "public counsellor listing" on profiles
  for select using (is_public_listed = true);
-- Admins can see and manage everyone.
create policy "admin manages profiles" on profiles
  for all using (current_role_name() = 'admin');

-- ---------- cases ----------
-- Volunteers can see every case (they run triage).
create policy "volunteers see all cases" on cases
  for select using (current_role_name() in ('volunteer','admin'));
-- Volunteers can insert new cases (simulating the WhatsApp bot, or manual log)
-- and update tags/severity/assignment during triage.
create policy "volunteers manage cases" on cases
  for insert with check (current_role_name() in ('volunteer','admin'));
create policy "volunteers update cases" on cases
  for update using (current_role_name() in ('volunteer','admin'));
-- Counsellors can ONLY see cases assigned to them. This is the core privacy rule.
create policy "counsellors see own cases" on cases
  for select using (assigned_to = auth.uid());
-- Counsellors can update status/notes only on their own assigned cases.
create policy "counsellors update own cases" on cases
  for update using (assigned_to = auth.uid());

-- ---------- case_updates ----------
-- Visible to whoever can see the parent case (volunteers = all, counsellors = their own).
create policy "read updates via parent case" on case_updates
  for select using (
    exists (
      select 1 from cases c
      where c.id = case_updates.case_id
      and (current_role_name() in ('volunteer','admin') or c.assigned_to = auth.uid())
    )
  );
create policy "add updates to accessible cases" on case_updates
  for insert with check (
    exists (
      select 1 from cases c
      where c.id = case_updates.case_id
      and (current_role_name() in ('volunteer','admin') or c.assigned_to = auth.uid())
    )
  );

-- ---------- crisis_alerts ----------
create policy "team reads crisis alerts" on crisis_alerts
  for select using (current_role_name() in ('volunteer','counsellor','admin'));

-- ---------- media ----------
-- Public (anonymous) read for published pieces — this is what the public
-- Voices page and homepage preview query.
create policy "public reads published media" on media
  for select using (published = true);
-- Only the media manager / admin can add or edit.
create policy "media manager writes" on media
  for insert with check (current_role_name() in ('media_manager','admin'));
create policy "media manager updates" on media
  for update using (current_role_name() in ('media_manager','admin'));
create policy "media manager deletes" on media
  for delete using (current_role_name() in ('media_manager','admin'));

-- ============================================================
-- AUTO-CREATE PENDING PROFILE ON SELF-SIGNUP (/join page)
-- ============================================================
-- New team members sign up themselves (email + password) via /join.
-- This creates their auth.users row. This trigger then creates a matching
-- profiles row automatically — starting as an INACTIVE volunteer until an
-- admin reviews them in /admin, sets their real role, and activates them.
-- security definer means this runs with elevated privileges and bypasses
-- RLS, which is required since the new user has no profile (and therefore
-- no role) yet at the moment this fires.
create or replace function handle_new_user() returns trigger as $$
begin
  insert into public.profiles (id, email, full_name, role, is_active)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'full_name', new.email),
    'volunteer',
    false
  );
  return new;
end;
$$ language plpgsql security definer;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function handle_new_user();

-- ============================================================
-- USEFUL INDEXES
-- ============================================================
create index idx_cases_status on cases(status);
create index idx_cases_severity on cases(severity);
create index idx_cases_assigned_to on cases(assigned_to);
create index idx_cases_tags on cases using gin(tags);
create index idx_media_tag on media(tag);
create index idx_media_published on media(published);
create index idx_profiles_is_active on profiles(is_active);
create index idx_profiles_role on profiles(role);

-- ============================================================
-- AUTO-GENERATE case_ref (e.g. SR-1042) ON INSERT
-- ============================================================
create sequence case_ref_seq start 1042;
create or replace function set_case_ref() returns trigger as $$
begin
  if new.case_ref is null then
    new.case_ref := 'SR-' || nextval('case_ref_seq');
  end if;
  return new;
end;
$$ language plpgsql;

create trigger trg_set_case_ref before insert on cases
  for each row execute function set_case_ref();
