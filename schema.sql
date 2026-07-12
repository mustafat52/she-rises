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
create type case_source as enum ('whatsapp_bot', 'manual', 'web_form', 'chat');
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
-- CHAT SYSTEM (replaces WhatsApp bot intake)
-- ============================================================
-- A woman never creates an account. She gets a private, unguessable
-- access_code tied to her case, and uses it to resume the same
-- conversation later. All access for her is through the security
-- definer functions below — NOT through direct table RLS — because
-- she has no auth.uid() to check against.

alter table cases add column if not exists access_code text unique;
alter table profiles add column if not exists is_away boolean not null default false;

create type message_sender as enum ('seeker', 'volunteer', 'counsellor');

create table case_messages (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references cases(id) on delete cascade,
  sender_type message_sender not null,
  sender_id uuid references profiles(id), -- null when sender_type = 'seeker'
  body text not null,
  created_at timestamptz not null default now()
);

alter table case_messages enable row level security;

-- Staff access mirrors the existing cases policies: volunteers/admins see
-- every conversation, counsellors only see messages on cases assigned to them.
create policy "staff read messages via parent case" on case_messages
  for select using (
    exists (
      select 1 from cases c
      where c.id = case_messages.case_id
      and (current_role_name() in ('volunteer','admin') or c.assigned_to = auth.uid())
    )
  );

create policy "staff send messages on accessible cases" on case_messages
  for insert with check (
    sender_type in ('volunteer','counsellor')
    and exists (
      select 1 from cases c
      where c.id = case_messages.case_id
      and (current_role_name() in ('volunteer','admin') or c.assigned_to = auth.uid())
    )
  );

-- No direct anon policy on cases/case_messages for the seeker side —
-- everything she does goes through these three functions instead.

-- ---------- helper: generate a short, unguessable, typeable code ----------
create or replace function generate_access_code() returns text as $$
declare
  alphabet text := 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; -- no O/0, I/1 — avoids typos
  code text := '';
  i int;
begin
  for i in 1..10 loop
    code := code || substr(alphabet, floor(random() * length(alphabet) + 1)::int, 1);
  end loop;
  return code;
end;
$$ language plpgsql;

-- ---------- start a new conversation (called by the public chat page) ----------
create or replace function start_conversation(first_message text)
returns table(out_access_code text, out_case_ref text) as $$
declare
  v_code text;
  v_case_id uuid;
  v_case_ref text;
  v_assignee uuid;
begin
  -- pick the active, non-away volunteer with the fewest currently-open cases
  select p.id into v_assignee
  from profiles p
  where p.role = 'volunteer' and p.is_active = true and p.is_away = false
  order by (
    select count(*) from cases c
    where c.assigned_to = p.id and c.status not in ('resolved','closed')
  ) asc
  limit 1;

  v_code := generate_access_code();
  -- extremely unlikely to collide given the keyspace, but guard anyway
  while exists (select 1 from cases where access_code = v_code) loop
    v_code := generate_access_code();
  end loop;

  insert into cases (alias, note, source, status, severity, assigned_to, access_code)
  values ('Anonymous conversation', first_message, 'chat', 'new', 'standard', v_assignee, v_code)
  returning id, case_ref into v_case_id, v_case_ref;

  insert into case_messages (case_id, sender_type, body)
  values (v_case_id, 'seeker', first_message);

  return query select v_code, v_case_ref;
end;
$$ language plpgsql security definer;

-- ---------- resume a conversation (validates the code, returns everything) ----------
create or replace function get_conversation(p_access_code text)
returns table(
  case_ref text, status case_status, severity case_severity,
  assigned_name text, message_id uuid, sender_type message_sender, body text, sent_at timestamptz
) as $$
begin
  return query
  select c.case_ref, c.status, c.severity, p.full_name,
         m.id, m.sender_type, m.body, m.created_at
  from cases c
  left join profiles p on p.id = c.assigned_to
  join case_messages m on m.case_id = c.id
  where c.access_code = p_access_code
  order by m.created_at asc;
end;
$$ language plpgsql security definer;

-- ---------- send a message as the seeker (validates the code before inserting) ----------
create or replace function send_message_as_seeker(p_access_code text, p_body text)
returns boolean as $$
declare
  v_case_id uuid;
begin
  select id into v_case_id from cases where access_code = p_access_code;
  if v_case_id is null then
    return false;
  end if;
  insert into case_messages (case_id, sender_type, body)
  values (v_case_id, 'seeker', p_body);
  update cases set updated_at = now() where id = v_case_id;
  return true;
end;
$$ language plpgsql security definer;

create index idx_case_messages_case_id on case_messages(case_id);
create index idx_cases_access_code on cases(access_code);

-- ============================================================
-- COUNSELLOR APPLICATIONS
-- ============================================================
-- Counsellors don't get the lightweight self-signup/approve path that
-- volunteers and the media manager get. They submit a real application —
-- credentials, license, motivation — reviewed by an admin or any
-- already-approved counsellor before their account is ever activated
-- as a counsellor.

create type application_status as enum ('pending', 'approved', 'rejected');

create table counsellor_applications (
  id uuid primary key default gen_random_uuid(),
  applicant_id uuid not null references auth.users(id) on delete cascade,

  full_name text not null,
  email text not null,
  phone text,
  qualification text,
  institution text,
  license_number text,
  license_document_path text,   -- path within the private storage bucket, not a public URL
  years_experience text,
  current_practice text,
  specialties text[] default '{}',
  languages text,
  location text,
  motivation_statement text,
  weekly_availability text,
  confidentiality_consent boolean not null default false,

  status application_status not null default 'pending',
  reviewed_by uuid references profiles(id),
  reviewed_at timestamptz,
  rejection_reason text,

  created_at timestamptz not null default now()
);

alter table counsellor_applications enable row level security;

-- The applicant can see their own application(s), to check status/reason.
create policy "applicant reads own applications" on counsellor_applications
  for select using (applicant_id = auth.uid());

-- The applicant can submit (insert) their own application.
create policy "applicant submits application" on counsellor_applications
  for insert with check (applicant_id = auth.uid());

-- Admins or any already-approved counsellor can see and review every application.
create policy "reviewers read all applications" on counsellor_applications
  for select using (current_role_name() in ('admin','counsellor'));

create policy "reviewers update applications" on counsellor_applications
  for update using (current_role_name() in ('admin','counsellor'));

-- ---------- Private storage for license/certificate documents ----------
insert into storage.buckets (id, name, public)
values ('counsellor-documents', 'counsellor-documents', false)
on conflict (id) do nothing;

-- Applicants can upload only into their own folder (path starts with their user id).
create policy "applicant uploads own documents" on storage.objects
  for insert with check (
    bucket_id = 'counsellor-documents'
    and (storage.foldername(name))[1] = auth.uid()::text
  );

-- Only admins/counsellors can read these documents — never public, and
-- not even the applicant themselves can read it back (avoids needing to
-- distinguish "their own" vs "everyone's" read access on a sensitive
-- document; they already have their own copy of what they uploaded).
create policy "reviewers read documents" on storage.objects
  for select using (
    bucket_id = 'counsellor-documents'
    and current_role_name() in ('admin','counsellor')
  );

create index idx_counsellor_applications_status on counsellor_applications(status);
create index idx_counsellor_applications_applicant on counsellor_applications(applicant_id);

-- ============================================================
-- GENERAL CONTRIBUTOR INTEREST (/volunteer)
-- ============================================================
-- Distinct from the team accounts above — this is for anyone who wants
-- to help in some way (doctor, lawyer, social media, design, etc.) but
-- isn't signing up for helpline duty or applying as a counsellor. No
-- account is created; it's just a contact list for admins to follow up
-- with by email.

create table contribution_interest (
  id uuid primary key default gen_random_uuid(),
  full_name text not null,
  email text not null,
  profession text not null,
  message text,
  contacted boolean not null default false,
  contacted_by uuid references profiles(id),
  contacted_at timestamptz,
  created_at timestamptz not null default now()
);

alter table contribution_interest enable row level security;

-- Anyone (anonymous, no login) can submit the form.
create policy "public submits contribution interest" on contribution_interest
  for insert with check (true);

-- Only admins can see or manage the resulting list.
create policy "admin reads contribution interest" on contribution_interest
  for select using (current_role_name() = 'admin');

create policy "admin updates contribution interest" on contribution_interest
  for update using (current_role_name() = 'admin');

create index idx_contribution_interest_contacted on contribution_interest(contacted);

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