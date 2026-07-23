-- ============================================================
-- Campaign Site Factory v6 - Factory Control Plane Migration
-- ============================================================

create extension if not exists "uuid-ossp";
create extension if not exists pgcrypto;

-- ============================================================
-- Factory Settings
-- ============================================================
create table if not exists factory_settings (
  id boolean primary key default true check (id),
  base_domain text not null default 'campaigns.example.com',
  default_primary_color text not null default '#15803d',
  default_secondary_color text not null default '#d97706',
  default_theme_mode text not null default 'dark' check (default_theme_mode in ('dark','light')),
  default_enabled_share_platforms jsonb not null default '["x","whatsapp","facebook","telegram"]'::jsonb,
  require_2fa boolean not null default true,
  updated_at timestamptz not null default now()
);

insert into factory_settings default values
on conflict (id) do nothing;

-- ============================================================
-- Super Admins
-- ============================================================
create table if not exists super_admins (
  id uuid primary key default uuid_generate_v4(),
  username text not null unique,
  password_hash text not null,
  password_salt text not null,
  totp_secret_encrypted text,
  totp_enabled boolean not null default false,
  must_enroll_totp boolean not null default true,
  must_change_password boolean not null default true,
  failed_login_attempts integer not null default 0,
  locked_until timestamptz,
  password_changed_at timestamptz,
  is_active boolean not null default true,
  last_login_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

do $$
begin
  alter table super_admins add column if not exists totp_secret_encrypted text;
  alter table super_admins add column if not exists must_enroll_totp boolean not null default true;
  alter table super_admins add column if not exists must_change_password boolean not null default true;
  alter table super_admins add column if not exists failed_login_attempts integer not null default 0;
  alter table super_admins add column if not exists locked_until timestamptz;
  alter table super_admins add column if not exists password_changed_at timestamptz;
exception when duplicate_column then null;
end $$;

-- ============================================================
-- Tenants
-- ============================================================
create table if not exists tenants (
  id uuid primary key default uuid_generate_v4(),
  org_name text not null,
  slug text not null unique,
  status text not null default 'creating' check (status in ('creating','active','suspended','failed','deleting')),
  description text default '',
  hashtag text default '',
  logo_url text default '',
  favicon_url text default '',
  primary_color text default '#15803d',
  secondary_color text default '#d97706',
  theme_mode text default 'dark' check (theme_mode in ('dark','light')),
  enabled_share_platforms jsonb default '["x","whatsapp","facebook","telegram"]'::jsonb,
  base_domain text,
  primary_domain text,
  vercel_project_id text,
  vercel_url text,
  supabase_project_ref text,
  supabase_project_url text,
  tenant_service_key_encrypted text,
  region text default 'us-east-1',
  custom_domain text,
  subdomain text,
  created_by uuid references super_admins(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  suspended_at timestamptz,
  deleted_at timestamptz
);

do $$
begin
  alter table tenants add column if not exists base_domain text;
  alter table tenants add column if not exists primary_domain text;
  alter table tenants add column if not exists tenant_service_key_encrypted text;
  alter table tenants add column if not exists region text default 'us-east-1';
exception when duplicate_column then null;
end $$;

create index if not exists idx_tenants_slug on tenants(slug);
create index if not exists idx_tenants_status on tenants(status);
create index if not exists idx_tenants_primary_domain on tenants(primary_domain);

-- ============================================================
-- Tenant Domains
-- ============================================================
create table if not exists tenant_domains (
  id uuid primary key default uuid_generate_v4(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  hostname text not null unique,
  domain_type text not null check (domain_type in ('subdomain','custom')),
  status text not null default 'pending' check (status in ('pending','pending_verification','verified','failed')),
  verification jsonb default '{}'::jsonb,
  is_primary boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_tenant_domains_tenant on tenant_domains(tenant_id);
create index if not exists idx_tenant_domains_hostname on tenant_domains(hostname);

-- ============================================================
-- Super Admin Sessions
-- ============================================================
create table if not exists super_admin_sessions (
  id serial primary key,
  session_token_hash text not null unique,
  super_admin_id uuid not null references super_admins(id) on delete cascade,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);

create index if not exists idx_super_admin_sessions_token on super_admin_sessions(session_token_hash);

-- ============================================================
-- Provisioning Jobs
-- ============================================================
create table if not exists provisioning_jobs (
  id uuid primary key default uuid_generate_v4(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  step text not null default 'init',
  status text not null default 'running' check (status in ('running','completed','failed','rolled_back')),
  progress integer default 0,
  error_log text,
  retry_count integer not null default 0,
  idempotency_key text unique,
  started_at timestamptz not null default now(),
  completed_at timestamptz,
  created_by uuid references super_admins(id)
);

do $$
begin
  alter table provisioning_jobs add column if not exists retry_count integer not null default 0;
  alter table provisioning_jobs add column if not exists idempotency_key text;
exception when duplicate_column then null;
end $$;

create index if not exists idx_provisioning_jobs_tenant on provisioning_jobs(tenant_id);
create index if not exists idx_provisioning_jobs_status on provisioning_jobs(status);

-- ============================================================
-- Factory Activity Logs (immutable audit trail)
-- ============================================================
create table if not exists factory_activity_logs (
  id serial primary key,
  super_admin_id uuid references super_admins(id) on delete set null,
  tenant_id uuid references tenants(id) on delete set null,
  action_type text not null,
  details jsonb,
  ip_address text,
  user_agent text,
  created_at timestamptz not null default now()
);

create index if not exists idx_factory_logs_admin on factory_activity_logs(super_admin_id);
create index if not exists idx_factory_logs_tenant on factory_activity_logs(tenant_id);
create index if not exists idx_factory_logs_action on factory_activity_logs(action_type);
create index if not exists idx_factory_logs_created on factory_activity_logs(created_at);

create or replace function prevent_factory_log_modification()
returns trigger as $$
begin
  raise exception 'Factory activity logs are immutable';
  return null;
end;
$$ language plpgsql;

drop trigger if exists trg_factory_logs_immutable on factory_activity_logs;
create trigger trg_factory_logs_immutable
before update or delete on factory_activity_logs
for each row execute function prevent_factory_log_modification();

-- ============================================================
-- Secrets Vault
-- ============================================================
create table if not exists secrets_vault (
  id uuid primary key default uuid_generate_v4(),
  key_name text not null unique,
  encrypted_value text not null,
  description text default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- ============================================================
-- Rate Limits
-- ============================================================
create table if not exists rate_limits (
  key text primary key,
  count integer not null default 1,
  window_start timestamptz not null default now()
);

create or replace function factory_check_rate_limit(
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
