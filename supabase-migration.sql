-- ============================================================
-- RDP Campaign Management System v4 - Database Migration
-- ============================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- 1. Sub-Admins Table
-- ============================================================
CREATE TABLE IF NOT EXISTS sub_admins (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT true,
  permissions JSONB NOT NULL DEFAULT '{"canAddTweets": true, "canEditTweets": true, "canDeleteTweets": false, "canImportExcel": true, "canViewReports": false}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ
);

-- ============================================================
-- 2. Admin Sessions Table
-- ============================================================
CREATE TABLE IF NOT EXISTS admin_sessions (
  id SERIAL PRIMARY KEY,
  session_token_hash TEXT NOT NULL UNIQUE,
  admin_type TEXT NOT NULL CHECK (admin_type IN ('main', 'sub')),
  sub_admin_id INTEGER REFERENCES sub_admins(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_token ON admin_sessions(session_token_hash);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_sub_admin ON admin_sessions(sub_admin_id);

-- ============================================================
-- 3. Admin Activity Logs Table
-- ============================================================
CREATE TABLE IF NOT EXISTS admin_activity_logs (
  id SERIAL PRIMARY KEY,
  admin_type TEXT NOT NULL CHECK (admin_type IN ('main', 'sub')),
  sub_admin_id INTEGER REFERENCES sub_admins(id) ON DELETE SET NULL,
  admin_name TEXT,
  action_type TEXT NOT NULL CHECK (action_type IN (
    'login', 'logout', 'add_tweet', 'edit_tweet', 'delete_tweet',
    'import_excel', 'create_campaign', 'edit_campaign', 'delete_campaign',
    'create_invite', 'download_report', 'create_sub_admin', 'edit_sub_admin',
    'toggle_sub_admin'
  )),
  campaign_id INTEGER,
  tweet_id INTEGER,
  details JSONB,
  ip_address TEXT,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_activity_logs_admin ON admin_activity_logs(sub_admin_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_action ON admin_activity_logs(action_type);
CREATE INDEX IF NOT EXISTS idx_activity_logs_campaign ON admin_activity_logs(campaign_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_created ON admin_activity_logs(created_at);

-- ============================================================
-- 4. Invite Links Table
-- ============================================================
CREATE TABLE IF NOT EXISTS invite_links (
  id SERIAL PRIMARY KEY,
  campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  code TEXT NOT NULL UNIQUE,
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_by_type TEXT NOT NULL CHECK (created_by_type IN ('main', 'sub')),
  created_by_sub_admin_id INTEGER REFERENCES sub_admins(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invite_links_campaign ON invite_links(campaign_id);
CREATE INDEX IF NOT EXISTS idx_invite_links_code ON invite_links(code);

-- ============================================================
-- 5. Analytics Events Table
-- ============================================================
CREATE TABLE IF NOT EXISTS analytics_events (
  id SERIAL PRIMARY KEY,
  event_type TEXT NOT NULL CHECK (event_type IN (
    'page_view', 'campaign_view', 'tweet_share_click', 'tweet_copy',
    'invite_visit', 'report_download'
  )),
  campaign_id INTEGER,
  tweet_id INTEGER,
  invite_code TEXT,
  visitor_id TEXT,
  metadata JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analytics_campaign ON analytics_events(campaign_id);
CREATE INDEX IF NOT EXISTS idx_analytics_event_type ON analytics_events(event_type);
CREATE INDEX IF NOT EXISTS idx_analytics_invite ON analytics_events(invite_code);
CREATE INDEX IF NOT EXISTS idx_analytics_visitor ON analytics_events(visitor_id);
CREATE INDEX IF NOT EXISTS idx_analytics_created ON analytics_events(created_at);

-- ============================================================
-- 6. Update existing tweets table
-- ============================================================
DO $$ BEGIN
  ALTER TABLE tweets ADD COLUMN IF NOT EXISTS created_by_type TEXT CHECK (created_by_type IN ('main', 'sub'));
  ALTER TABLE tweets ADD COLUMN IF NOT EXISTS created_by_sub_admin_id INTEGER REFERENCES sub_admins(id) ON DELETE SET NULL;
  ALTER TABLE tweets ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;
EXCEPTION
  WHEN duplicate_column THEN NULL;
END $$;

-- ============================================================
-- 6.5. Add index for analytics event_type queries (new multi-platform events)
CREATE INDEX IF NOT EXISTS idx_analytics_event_type ON analytics_events(event_type);
CREATE INDEX IF NOT EXISTS idx_analytics_created_at ON analytics_events(created_at);

-- Note: New event_types added in v4.1:
--   'tweet_share_x', 'tweet_share_whatsapp', 'tweet_share_facebook',
--   'tweet_share_telegram', 'tweet_share_native',
--   'tweet_save_image', 'qr_download', 'campaign_link_copy', 'qr_modal_open'
-- The analytics_events table stores event_type as TEXT, so no schema change needed.

-- ============================================================
-- 7. Ensure campaigns table has all needed columns
-- ============================================================
DO $$ BEGIN
  ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS description TEXT;
  ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true;
  ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS target_time TIMESTAMPTZ;
  ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS end_time TIMESTAMPTZ;
  ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS target_timezone TEXT DEFAULT 'Asia/Riyadh';
  ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS timezone_label TEXT DEFAULT 'توقيت مكة المكرمة (GMT+3)';
  ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS video_url TEXT;
  ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS hashtag TEXT;
  ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
  ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
EXCEPTION
  WHEN duplicate_column THEN NULL;
END $$;

-- ============================================================
-- 8. Create helper function for invite stats
-- ============================================================
CREATE OR REPLACE FUNCTION get_invite_stats(p_campaign_id INTEGER, p_code TEXT)
RETURNS TABLE (
  total_visits BIGINT,
  unique_visitors BIGINT,
  share_clicks BIGINT,
  last_visit TIMESTAMPTZ
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    COUNT(*)::BIGINT AS total_visits,
    COUNT(DISTINCT ae.visitor_id)::BIGINT AS unique_visitors,
    COUNT(DISTINCT CASE WHEN ae.event_type = 'tweet_share_click' THEN ae.id END)::BIGINT AS share_clicks,
    -- ملاحظة: أنواع الأحداث الجديدة للمشاركة (v4.1):
    -- tweet_share_x, tweet_share_whatsapp, tweet_share_facebook, tweet_share_telegram, tweet_share_native
    -- tweet_save_image, qr_download, campaign_link_copy, qr_modal_open
    -- يمكن استخدام ae.event_type LIKE 'tweet_share_%' لحساب جميع المشاركات
    MAX(ae.created_at) AS last_visit
  FROM analytics_events ae
  WHERE ae.campaign_id = p_campaign_id
    AND ae.invite_code = p_code;
END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- 9. Create function to clean expired sessions
-- ============================================================
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  DELETE FROM admin_sessions
  WHERE expires_at < NOW() OR revoked_at IS NOT NULL;
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;
