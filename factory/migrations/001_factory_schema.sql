-- ============================================================
-- Campaign Site Factory — Factory Control Plane schema
-- Run this against the FACTORY's own Render Postgres database — never against
-- a tenant's project. This database holds no campaign data; it only
-- tracks which tenants exist and how to reach them.
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- 1. tenants — one row per provisioned media-org site (PRD §9a)
-- ============================================================
CREATE TABLE IF NOT EXISTS tenants (
  id SERIAL PRIMARY KEY,
  org_name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,                    -- used for subdomain + Vercel project name
  status TEXT NOT NULL DEFAULT 'provisioning'
    CHECK (status IN ('provisioning', 'active', 'suspended', 'failed', 'deleting', 'deleted')),
  vercel_project_id TEXT,
  vercel_project_name TEXT,
  vercel_url TEXT,
  schema_name TEXT,   -- e.g. 'tenant_42' — this tenant's dedicated schema on the ONE shared Postgres server
  custom_domain TEXT,
  enabled_share_platforms JSONB NOT NULL DEFAULT '["x","whatsapp","facebook"]'::jsonb,
  template_git_sha TEXT,                        -- which commit of the tenant template this tenant is deployed at
  created_by_super_admin_id INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  suspended_at TIMESTAMPTZ,
  deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);
CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);

-- ============================================================
-- 2. provisioning_jobs — step-by-step tracking of the async pipeline (§7b)
-- ============================================================
CREATE TABLE IF NOT EXISTS provisioning_jobs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
  job_type TEXT NOT NULL DEFAULT 'create'
    CHECK (job_type IN ('create', 'update_template', 'bulk_update_template', 'delete', 'reset_admin_password')),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'rolled_back')),
  current_step TEXT,
  steps JSONB NOT NULL DEFAULT '[]'::jsonb,      -- ordered log: [{step, status, startedAt, completedAt, error}]
  input_payload JSONB,                            -- wizard input for 'create' jobs (never includes secrets)
  error_message TEXT,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_provisioning_jobs_tenant ON provisioning_jobs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_provisioning_jobs_status ON provisioning_jobs(status);

-- ============================================================
-- 3. super_admins — factory operators only (our team), 2FA required (§11 item 3)
-- ============================================================
CREATE TABLE IF NOT EXISTS super_admins (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  totp_secret_encrypted TEXT,                     -- AES-256-GCM ciphertext, see lib/secretsVault.js
  totp_enrolled_at TIMESTAMPTZ,
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ
);

-- ============================================================
-- 4. factory_activity_logs — append-only audit trail (§11 item 5)
-- No UPDATE/DELETE grants should ever be issued on this table from the
-- application role; only INSERT and SELECT. Enforce that at the DB role
-- level in addition to the application never calling update()/delete().
-- ============================================================
CREATE TABLE IF NOT EXISTS factory_activity_logs (
  id BIGSERIAL PRIMARY KEY,
  super_admin_id INTEGER REFERENCES super_admins(id) ON DELETE SET NULL,
  super_admin_name TEXT,
  tenant_id INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
  action_type TEXT NOT NULL,   -- e.g. 'login', 'create_tenant', 'suspend_tenant', 'delete_tenant',
                                -- 'reset_admin_password', 'update_template', 'bulk_update_template'
  details JSONB,
  ip_address TEXT,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_factory_logs_tenant ON factory_activity_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_factory_logs_admin ON factory_activity_logs(super_admin_id);
CREATE INDEX IF NOT EXISTS idx_factory_logs_created ON factory_activity_logs(created_at);

-- ============================================================
-- 5. secrets_vault — encrypted Vercel/Render master tokens (§11 item 1)
-- Values are AES-256-GCM ciphertext produced by lib/secretsVault.js using
-- FACTORY_MASTER_KEY (an env var, never stored in this table or in git).
-- Per-tenant database connection strings are also stored here, keyed as
-- 'tenant:<tenant_id>:database_url', so they never sit in
-- provisioning_jobs.input_payload or any log.
-- ============================================================
CREATE TABLE IF NOT EXISTS secrets_vault (
  id SERIAL PRIMARY KEY,
  key_name TEXT NOT NULL UNIQUE,
  encrypted_value TEXT NOT NULL,     -- format: "<iv_hex>:<authtag_hex>:<ciphertext_hex>"
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  rotated_at TIMESTAMPTZ
);

-- ============================================================
-- 6. admin_sessions — factory dashboard sessions (mirrors tenant-side pattern)
-- ============================================================
CREATE TABLE IF NOT EXISTS factory_sessions (
  id SERIAL PRIMARY KEY,
  session_token_hash TEXT NOT NULL UNIQUE,
  super_admin_id INTEGER NOT NULL REFERENCES super_admins(id) ON DELETE CASCADE,
  totp_verified BOOLEAN NOT NULL DEFAULT false,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_factory_sessions_token ON factory_sessions(session_token_hash);

CREATE OR REPLACE FUNCTION cleanup_expired_factory_sessions()
RETURNS INTEGER AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  DELETE FROM factory_sessions WHERE expires_at < NOW() OR revoked_at IS NOT NULL;
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;
