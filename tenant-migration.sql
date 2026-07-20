-- ============================================================
-- Campaign Site Factory - Tenant DB Additions
-- Run this on EACH tenant's Supabase project after creation
-- Adds site_settings table + main_admins table
-- ============================================================

-- ============================================================
-- 1. Site Settings (single row per tenant, visual identity)
-- ============================================================
CREATE TABLE IF NOT EXISTS site_settings (
  id SERIAL PRIMARY KEY,
  org_name TEXT NOT NULL DEFAULT 'اسم الحملة',
  hashtag TEXT DEFAULT '',
  logo_url TEXT DEFAULT '/logo-dark.png',
  favicon_url TEXT DEFAULT '/favicon.ico',
  primary_color TEXT DEFAULT '#15803d',
  secondary_color TEXT DEFAULT '#d97706',
  theme_mode TEXT DEFAULT 'dark' CHECK (theme_mode IN ('dark', 'light')),
  enabled_share_platforms JSONB DEFAULT '["x","whatsapp","facebook","telegram"]'::jsonb,
  social_links JSONB DEFAULT '{}'::jsonb,
  meta_title TEXT DEFAULT '',
  meta_description TEXT DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Insert default settings
INSERT INTO site_settings (org_name) VALUES ('اسم الحملة')
ON CONFLICT DO NOTHING;

-- ============================================================
-- 2. Main Admins (move from env var to encrypted DB storage)
-- ============================================================
CREATE TABLE IF NOT EXISTS main_admins (
  id SERIAL PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT true,
  must_change_password BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ
);

-- ============================================================
-- 3. Update analytics_events to track platform per share
-- ============================================================
DO $$ BEGIN
  ALTER TABLE analytics_events ADD COLUMN IF NOT EXISTS platform TEXT;
EXCEPTION
  WHEN duplicate_column THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_analytics_platform ON analytics_events(platform);
