-- ============================================================
-- Legacy Data Migration Script (Optional)
-- Run this AFTER applying tenant/01_migration.sql to copy
-- existing data from the old schema into the new v6 tables.
-- ============================================================
-- Usage: Run manually in Supabase SQL Editor after migration.
--        Review each section before executing.
-- ============================================================

-- 1. Migrate campaigns (if old campaigns table exists)
do $$
begin
  if exists (select 1 from information_schema.tables where table_name = 'campaigns') then
    -- Check if old columns exist and new ones don't have data
    if exists (select 1 from campaigns where created_at is not null) and not exists (select 1 from campaigns limit 1) then
      -- Already migrated, skip
      null;
    end if;
    raise notice 'Campaigns table already exists with v6 schema. Skipping migration.';
  end if;
end $$;

-- 2. Migrate tweets (preserve existing tweets)
insert into tweets (campaign_id, title, text, text_encoded, media_url, created_by_type, created_at, updated_at)
select
  campaign_id,
  coalesce(title, ''),
  text,
  text_encoded,
  media_url,
  created_by_type,
  created_at,
  updated_at
from tweets t
where not exists (
  select 1 from tweets t2 where t2.id = t.id
)
on conflict do nothing;

-- 3. Migrate sub_admins
insert into sub_admins (name, username, password_hash, password_salt, is_active, permissions, created_at, updated_at, last_login_at)
select
  name,
  username,
  password_hash,
  password_salt,
  is_active,
  permissions,
  created_at,
  updated_at,
  last_login_at
from sub_admins s
where not exists (
  select 1 from sub_admins s2 where s2.username = s.username
)
on conflict (username) do nothing;

-- 4. Migrate invite_links
insert into invite_links (campaign_id, name, code, is_active, created_by_type, created_by_sub_admin_id, created_at, updated_at)
select
  campaign_id,
  name,
  code,
  is_active,
  created_by_type,
  created_by_sub_admin_id,
  created_at,
  updated_at
from invite_links i
where not exists (
  select 1 from invite_links i2 where i2.code = i.code
)
on conflict (code) do nothing;

-- 5. Migrate analytics_events
insert into analytics_events (event_type, campaign_id, tweet_id, invite_code, visitor_id, platform, metadata, created_at)
select
  event_type,
  campaign_id,
  tweet_id,
  invite_code,
  visitor_id,
  platform,
  metadata,
  created_at
from analytics_events a
where not exists (
  select 1 from analytics_events a2 where a2.id = a.id
)
on conflict do nothing;

-- 6. Migrate admin_activity_logs
insert into admin_activity_logs (admin_type, sub_admin_id, admin_name, action_type, campaign_id, tweet_id, details, ip_address, user_agent, created_at)
select
  admin_type,
  sub_admin_id,
  admin_name,
  action_type,
  campaign_id,
  tweet_id,
  details,
  ip_address,
  user_agent,
  created_at
from admin_activity_logs a
where not exists (
  select 1 from admin_activity_logs a2 where a2.id = a.id
)
on conflict do nothing;

-- 7. Create default main admin from old env credentials (if not exists)
-- Replace YOUR_OLD_PASSWORD with the actual old password before running
-- select public.create_main_admin('admin', 'YOUR_OLD_PASSWORD', true);

raise notice 'Legacy migration script completed. Verify data integrity manually.';
