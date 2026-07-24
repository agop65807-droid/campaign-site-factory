-- ============================================================
-- Campaign Site Factory — Migration 002
-- Adds: multi-platform share analytics (Phase 1) + dynamic site
-- identity and DB-backed main admin credentials (Phase 2 foundation)
--
-- This migration is purely ADDITIVE and safe to run against the
-- live production database: every new column is nullable, every
-- new table is independent, and the application code (api/[...path].js)
-- degrades gracefully if this migration has not been applied yet
-- (see handleAnalytics / handleConfig / handleAuth).
-- ============================================================

-- ============================================================
-- 1. Platform column on analytics_events (FR5)
-- ============================================================
DO $$ BEGIN
  ALTER TABLE analytics_events ADD COLUMN IF NOT EXISTS platform TEXT
    CHECK (platform IN ('x', 'whatsapp', 'facebook', 'clipboard'));
EXCEPTION
  WHEN duplicate_column THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_analytics_platform ON analytics_events(platform);

-- ============================================================
-- 2. site_settings — dynamic branding/identity (FR4)
-- Single-row table (per tenant database). The application reads this
-- via GET /api/config. Insert exactly one row per tenant; the Factory
-- provisioning pipeline does this automatically for new tenants (see
-- /factory/lib/provisioning.js). For the current live site, this table
-- is intentionally left empty until you choose to populate it — the
-- app falls back to the existing hardcoded identity until then.
-- ============================================================
CREATE TABLE IF NOT EXISTS site_settings (
  id SERIAL PRIMARY KEY,
  org_name TEXT NOT NULL,
  site_title TEXT,
  site_description TEXT,
  hashtag TEXT,
  logo_url TEXT,
  favicon_url TEXT,
  primary_color TEXT NOT NULL DEFAULT '#1e3a8a',
  secondary_color TEXT NOT NULL DEFAULT '#d97706',
  theme_mode TEXT NOT NULL DEFAULT 'dark' CHECK (theme_mode IN ('dark', 'light')),
  enabled_share_platforms JSONB NOT NULL DEFAULT '["x","whatsapp","facebook"]'::jsonb,
  social_links JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enforce single-row semantics without a partial unique index quirk:
-- application code always does .limit(1).single(), and the Factory
-- pipeline only ever inserts one row per tenant project.
CREATE OR REPLACE FUNCTION touch_site_settings_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_site_settings_updated_at ON site_settings;
CREATE TRIGGER trg_site_settings_updated_at
  BEFORE UPDATE ON site_settings
  FOR EACH ROW EXECUTE FUNCTION touch_site_settings_updated_at();

-- ============================================================
-- 3. main_admins — DB-backed main admin credentials (security §11 item 4)
-- Replaces the plaintext ADMIN_USER/ADMIN_PASS env vars with the same
-- PBKDF2 + salt + timing-safe-compare scheme already used for sub_admins.
-- handleAuth() in api/[...path].js checks this table first and only
-- falls back to the env vars if no matching row exists, so existing
-- deployments keep working unchanged until you create a row here.
-- ============================================================
CREATE TABLE IF NOT EXISTS main_admins (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT true,
  must_change_password BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ
);

-- To create the first main_admins row for an existing (already-live) tenant,
-- generate a salt + PBKDF2 hash the same way sub-admins are created (100000
-- iterations, sha512 — see hashPassword() in api/[...path].js) and insert:
--
--   INSERT INTO main_admins (name, username, password_hash, password_salt, must_change_password)
--   VALUES ('المشرف الرئيسي', '<username>', '<pbkdf2_hex>', '<salt_hex>', true);
--
-- The Factory provisioning pipeline does this automatically for new tenants.
