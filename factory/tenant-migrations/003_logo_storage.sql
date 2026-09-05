-- ============================================================
-- Campaign Site Factory — Migration 003
-- Stores a small uploaded logo directly in the tenant's own Postgres
-- database — there's no separate managed file-storage service in this
-- architecture, and a single small logo image is well within reason to
-- keep in the database itself. Purely additive/nullable — safe on a
-- database that already has an uploaded logo_url pointing at an external
-- image, which keeps working.
-- ============================================================

DO $$ BEGIN
  ALTER TABLE site_settings ADD COLUMN IF NOT EXISTS logo_data_base64 TEXT;
  ALTER TABLE site_settings ADD COLUMN IF NOT EXISTS logo_content_type TEXT;
EXCEPTION
  WHEN duplicate_column THEN NULL;
END $$;

-- Served by GET /api/logo in api/[...path].js. When logo_data_base64 is set,
-- /api/logo takes precedence over site_settings.logo_url as the effective
-- logo source for a tenant.
