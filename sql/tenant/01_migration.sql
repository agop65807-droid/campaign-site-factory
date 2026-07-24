-- ============================================================
-- Tenant Database Migration v6
-- ============================================================

create extension if not exists "uuid-ossp";
create extension if not exists pgcrypto;

-- ============================================================
-- Campaigns
-- ============================================================
create table if not exists campaigns (
  id serial primary key,
  name text not null,
  description text default '',
  is_active boolean not null default true,
  target_time timestamptz,
  end_time timestamptz,
  target_timezone text default 'Asia/Riyadh',
  timezone_label text default 'توقيت مكة المكرمة (GMT+3)',
  video_url text default '',
  hashtag text default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- ============================================================
-- Tweets
-- ============================================================
create table if not exists tweets (
  id serial primary key,
  campaign_id integer not null references campaigns(id) on delete cascade,
  title text default '',
  text text not null,
  text_encoded text,
  media_url text,
  created_by_type text check (created_by_type in ('main','sub')),
  created_by_sub_admin_id integer references sub_admins(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz
);

-- ============================================================
-- Main Admins
-- ============================================================
create table if not exists main_admins (
  id serial primary key,
  username text not null unique,
  password_hash text not null,
  password_salt text not null,
  is_active boolean not null default true,
  must_change_password boolean not null default true,
  failed_login_attempts integer not null default 0,
  locked_until timestamptz,
  password_changed_at timestamptz,
  last_login_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- ============================================================
-- Sub Admins
-- ============================================================
create table if not exists sub_admins (
  id serial primary key,
  name text not null,
  username text not null unique,
  password_hash text not null,
  password_salt text not null,
  is_active boolean not null default true,
  permissions jsonb not null default '{"canAddTweets": true, "canEditTweets": true, "canDeleteTweets": false, "canImportExcel": true, "canViewReports": false}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_login_at timestamptz
);

-- ============================================================
-- Admin Sessions
-- ============================================================
create table if not exists admin_sessions (
  id serial primary key,
  session_token_hash text not null unique,
  admin_type text not null check (admin_type in ('main','sub')),
  sub_admin_id integer references sub_admins(id) on delete cascade,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);

create index if not exists idx_admin_sessions_token on admin_sessions(session_token_hash);

-- ============================================================
-- Admin Activity Logs (immutable audit trail)
-- ============================================================
create table if not exists admin_activity_logs (
  id serial primary key,
  admin_type text not null check (admin_type in ('main','sub')),
  sub_admin_id integer references sub_admins(id) on delete set null,
  admin_name text,
  action_type text not null,
  campaign_id integer,
  tweet_id integer,
  details jsonb,
  ip_address text,
  user_agent text,
  created_at timestamptz not null default now()
);

create index if not exists idx_activity_logs_admin on admin_activity_logs(sub_admin_id);
create index if not exists idx_activity_logs_action on admin_activity_logs(action_type);
create index if not exists idx_activity_logs_created on admin_activity_logs(created_at);

create or replace function prevent_admin_log_modification()
returns trigger as $$
begin
  raise exception 'Admin activity logs are immutable';
  return null;
end;
$$ language plpgsql;

drop trigger if exists trg_admin_logs_immutable on admin_activity_logs;
create trigger trg_admin_logs_immutable
before update or delete on admin_activity_logs
for each row execute function prevent_admin_log_modification();

-- ============================================================
-- Invite Links
-- ============================================================
create table if not exists invite_links (
  id serial primary key,
  campaign_id integer not null references campaigns(id) on delete cascade,
  name text not null,
  code text not null unique,
  is_active boolean not null default true,
  created_by_type text not null check (created_by_type in ('main','sub')),
  created_by_sub_admin_id integer references sub_admins(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- ============================================================
-- Analytics Events
-- ============================================================
create table if not exists analytics_events (
  id serial primary key,
  event_type text not null,
  campaign_id integer,
  tweet_id integer,
  invite_code text,
  visitor_id text,
  platform text,
  metadata jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_analytics_campaign on analytics_events(campaign_id);
create index if not exists idx_analytics_event_type on analytics_events(event_type);
create index if not exists idx_analytics_invite on analytics_events(invite_code);
create index if not exists idx_analytics_platform on analytics_events(platform);

-- ============================================================
-- Site Settings (single row per tenant, visual identity)
-- ============================================================
create table if not exists site_settings (
  id serial primary key,
  org_name text not null default 'اسم الحملة',
  hashtag text default '',
  logo_url text default '/logo-dark.png',
  favicon_url text default '/favicon.ico',
  primary_color text default '#15803d',
  secondary_color text default '#d97706',
  theme_mode text default 'dark' check (theme_mode in ('dark','light')),
  enabled_share_platforms jsonb default '["x","whatsapp","facebook","telegram"]'::jsonb,
  social_links jsonb default '{}'::jsonb,
  meta_title text default '',
  meta_description text default '',
  allow_admin_identity_edit boolean not null default false,
  updated_at timestamptz not null default now()
);

insert into site_settings (org_name)
values ('اسم الحملة')
on conflict do nothing;

-- ============================================================
-- Rate Limits
-- ============================================================
create table if not exists rate_limits (
  key text primary key,
  count integer not null default 1,
  window_start timestamptz not null default now()
);

create or replace function tenant_check_rate_limit(
  p_key text,
  p_max integer,
  p_window_seconds integer
)
returns table (allowed boolean, retry_after integer)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_now timestamptz := now();
  v_count integer;
  v_window_start timestamptz;
begin
  insert into rate_limits(key, count, window_start)
  values (p_key, 1, v_now)
  on conflict (key)
  do update set
    count = case
      when rate_limits.window_start < v_now - make_interval(secs => p_window_seconds) then 1
      else rate_limits.count + 1
    end,
    window_start = case
      when rate_limits.window_start < v_now - make_interval(secs => p_window_seconds) then v_now
      else rate_limits.window_start
    end
  returning rate_limits.count, rate_limits.window_start into v_count, v_window_start;

  if v_count > p_max then
    allowed := false;
    retry_after := greatest(1, ceil(extract(epoch from (v_window_start + make_interval(secs => p_window_seconds) - v_now)))::integer);
    return next;
  else
    allowed := true;
    retry_after := 0;
    return next;
  end if;
end;
$$;

-- ============================================================
-- Helper: create main admin safely
-- ============================================================
create or replace function create_main_admin(
  p_username text,
  p_password text,
  p_must_change boolean default true
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_salt text;
  v_hash text;
begin
  v_salt := encode(gen_random_bytes(32), 'hex');
  v_hash := encode(
    pbkdf2(p_password, decode(v_salt, 'hex'), 100000, 64, 'sha512'),
    'hex'
  );

  insert into main_admins (
    username,
    password_hash,
    password_salt,
    is_active,
    must_change_password
  )
  values (
    p_username,
    v_hash,
    v_salt,
    true,
    p_must_change
  )
  on conflict (username)
  do update set
    password_hash = excluded.password_hash,
    password_salt = excluded.password_salt,
    must_change_password = excluded.must_change_password,
    updated_at = now();
end;
$$;

-- ============================================================
-- Helper: upsert site settings
-- ============================================================
create or replace function upsert_site_settings(p jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into site_settings as s (
    id,
    org_name,
    hashtag,
    logo_url,
    favicon_url,
    primary_color,
    secondary_color,
    theme_mode,
    enabled_share_platforms,
    social_links,
    meta_title,
    meta_description,
    allow_admin_identity_edit,
    updated_at
  )
  values (
    1,
    coalesce(nullif(p->>'org_name', ''), 'اسم الحملة'),
    coalesce(p->>'hashtag', ''),
    coalesce(p->>'logo_url', '/logo-dark.png'),
    coalesce(p->>'favicon_url', '/favicon.ico'),
    coalesce(p->>'primary_color', '#15803d'),
    coalesce(p->>'secondary_color', '#d97706'),
    coalesce(p->>'theme_mode', 'dark'),
    coalesce(p->'enabled_share_platforms', '["x","whatsapp","facebook","telegram"]'::jsonb),
    coalesce(p->'social_links', '{}'::jsonb),
    coalesce(p->>'meta_title', ''),
    coalesce(p->>'meta_description', ''),
    coalesce((p->>'allow_admin_identity_edit')::boolean, false),
    now()
  )
  on conflict (id)
  do update set
    org_name = coalesce(nullif(p->>'org_name', ''), s.org_name),
    hashtag = coalesce(p->>'hashtag', s.hashtag),
    logo_url = coalesce(p->>'logo_url', s.logo_url),
    favicon_url = coalesce(p->>'favicon_url', s.favicon_url),
    primary_color = coalesce(p->>'primary_color', s.primary_color),
    secondary_color = coalesce(p->>'secondary_color', s.secondary_color),
    theme_mode = coalesce(p->>'theme_mode', s.theme_mode),
    enabled_share_platforms = coalesce(p->'enabled_share_platforms', s.enabled_share_platforms),
    social_links = coalesce(p->'social_links', s.social_links),
    meta_title = coalesce(p->>'meta_title', s.meta_title),
    meta_description = coalesce(p->>'meta_description', s.meta_description),
    allow_admin_identity_edit = coalesce((p->>'allow_admin_identity_edit')::boolean, s.allow_admin_identity_edit),
    updated_at = now();
end;
$$;

-- ============================================================
-- Add tenant_id for Multi-Tenant Shared Database support
-- ============================================================
do $$
begin
  alter table campaigns add column if not exists tenant_id uuid;
  alter table tweets add column if not exists tenant_id uuid;
  alter table main_admins add column if not exists tenant_id uuid;
  alter table sub_admins add column if not exists tenant_id uuid;
  alter table admin_sessions add column if not exists tenant_id uuid;
  alter table admin_activity_logs add column if not exists tenant_id uuid;
  alter table invite_links add column if not exists tenant_id uuid;
  alter table analytics_events add column if not exists tenant_id uuid;
  alter table site_settings add column if not exists tenant_id uuid;
exception when duplicate_column then null;
end $$;

create index if not exists idx_campaigns_tenant on campaigns(tenant_id);
create index if not exists idx_tweets_tenant on tweets(tenant_id);
create index if not exists idx_main_admins_tenant on main_admins(tenant_id);
create index if not exists idx_sub_admins_tenant on sub_admins(tenant_id);
create index if not exists idx_admin_sessions_tenant on admin_sessions(tenant_id);
create index if not exists idx_admin_activity_logs_tenant on admin_activity_logs(tenant_id);
create index if not exists idx_invite_links_tenant on invite_links(tenant_id);
create index if not exists idx_analytics_events_tenant on analytics_events(tenant_id);
create index if not exists idx_site_settings_tenant on site_settings(tenant_id);

-- ============================================================
-- Enable RLS (service_role bypasses, anon denied by default)
-- ============================================================
drop function if exists exec_sql(text);
drop function if exists exec_sql(text, jsonb);

alter table campaigns enable row level security;
alter table tweets enable row level security;
alter table main_admins enable row level security;
alter table sub_admins enable row level security;
alter table admin_sessions enable row level security;
alter table admin_activity_logs enable row level security;
alter table invite_links enable row level security;
alter table analytics_events enable row level security;
alter table site_settings enable row level security;
alter table rate_limits enable row level security;

-- Revoke public execution of security definer functions
revoke execute on all functions in schema public from public, anon, authenticated;
grant execute on function tenant_check_rate_limit(text, integer, integer) to service_role;
grant execute on function create_main_admin(text, text, boolean) to service_role;
grant execute on function upsert_site_settings(jsonb) to service_role;

revoke usage on schema public from public, anon, authenticated;
revoke all privileges on all tables in schema public from public, anon, authenticated;
revoke all privileges on all sequences in schema public from public, anon, authenticated;
grant usage on schema public to service_role;
grant all privileges on all tables in schema public to service_role;
grant all privileges on all sequences in schema public to service_role;

alter default privileges for role postgres in schema public
  revoke all privileges on tables from public, anon, authenticated;
alter default privileges for role postgres in schema public
  revoke all privileges on sequences from public, anon, authenticated;
alter default privileges for role postgres in schema public
  revoke execute on functions from public, anon, authenticated;
