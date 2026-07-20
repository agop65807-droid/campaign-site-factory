-- ============================================================
-- Campaign Site Factory - Factory Control Plane Migration
-- This runs on the FACTORY's own Supabase project (separate from tenants)
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- 1. Tenants Registry
-- ============================================================
CREATE TABLE IF NOT EXISTS tenants (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'creating' CHECK (status IN ('creating', 'active', 'suspended', 'failed', 'deleting')),
  description TEXT DEFAULT '',
  hashtag TEXT DEFAULT '',
  logo_url TEXT DEFAULT '',
  favicon_url TEXT DEFAULT '',
  primary_color TEXT DEFAULT '#15803d',
  secondary_color TEXT DEFAULT '#d97706',
  theme_mode TEXT DEFAULT 'dark' CHECK (theme_mode IN ('dark', 'light')),
  enabled_share_platforms JSONB DEFAULT '["x","whatsapp","facebook","telegram"]'::jsonb,
  vercel_project_id TEXT,
  vercel_url TEXT,
  supabase_project_ref TEXT,
  supabase_project_url TEXT,
  custom_domain TEXT,
  subdomain TEXT,
  created_by UUID REFERENCES super_admins(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  suspended_at TIMESTAMPTZ,
  deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);

-- ============================================================
-- 2. Super Admins
-- ============================================================
CREATE TABLE IF NOT EXISTS super_admins (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  totp_secret TEXT,
  totp_enabled BOOLEAN NOT NULL DEFAULT false,
  is_active BOOLEAN NOT NULL DEFAULT true,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- 3. Super Admin Sessions
-- ============================================================
CREATE TABLE IF NOT EXISTS super_admin_sessions (
  id SERIAL PRIMARY KEY,
  session_token_hash TEXT NOT NULL UNIQUE,
  super_admin_id UUID NOT NULL REFERENCES super_admins(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_super_admin_sessions_token ON super_admin_sessions(session_token_hash);

-- ============================================================
-- 4. Provisioning Jobs
-- ============================================================
CREATE TABLE IF NOT EXISTS provisioning_jobs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  step TEXT NOT NULL DEFAULT 'init',
  status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed', 'rolled_back')),
  progress INTEGER DEFAULT 0,
  error_log TEXT,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  created_by UUID REFERENCES super_admins(id)
);

CREATE INDEX IF NOT EXISTS idx_provisioning_jobs_tenant ON provisioning_jobs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_provisioning_jobs_status ON provisioning_jobs(status);

-- ============================================================
-- 5. Factory Activity Logs (immutable audit trail)
-- ============================================================
CREATE TABLE IF NOT EXISTS factory_activity_logs (
  id SERIAL PRIMARY KEY,
  super_admin_id UUID REFERENCES super_admins(id),
  tenant_id UUID REFERENCES tenants(id),
  action_type TEXT NOT NULL,
  details JSONB,
  ip_address TEXT,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_factory_logs_admin ON factory_activity_logs(super_admin_id);
CREATE INDEX IF NOT EXISTS idx_factory_logs_tenant ON factory_activity_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_factory_logs_action ON factory_activity_logs(action_type);
CREATE INDEX IF NOT EXISTS idx_factory_logs_created ON factory_activity_logs(created_at);

-- ============================================================
-- 6. Secrets Vault (encrypted API tokens)
-- ============================================================
CREATE TABLE IF NOT EXISTS secrets_vault (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  key_name TEXT NOT NULL UNIQUE,
  encrypted_value TEXT NOT NULL,
  description TEXT DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- 7. Factory Activity Log function (prevent updates/deletes)
-- ============================================================
CREATE OR REPLACE FUNCTION prevent_factory_log_modification()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Factory activity logs are immutable and cannot be modified or deleted';
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_factory_logs_immutable
  BEFORE UPDATE OR DELETE ON factory_activity_logs
  FOR EACH ROW
  EXECUTE FUNCTION prevent_factory_log_modification();
