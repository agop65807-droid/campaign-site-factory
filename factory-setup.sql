-- ============================================================
-- Campaign Site Factory - Initial Super Admin Setup
-- Run this ONCE on the factory Supabase project after migration
-- Default credentials: admin / ChangeMeNow!2026
-- IMPORTANT: Change these credentials immediately after first login!
-- ============================================================

-- Helper functions (must be in scope)
CREATE OR REPLACE FUNCTION generate_salt()
RETURNS TEXT AS $$
BEGIN
  RETURN encode(gen_random_bytes(32), 'hex');
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION hash_password(p_password TEXT, p_salt TEXT)
RETURNS TEXT AS $$
BEGIN
  RETURN encode(
    pbkdf2(p_password, decode(p_salt, 'hex'), 100000, 64, 'sha512'),
    'hex'
  );
END;
$$ LANGUAGE plpgsql;

-- Create default super admin
-- Username: admin
-- Password: ChangeMeNow!2026 (CHANGE THIS!)
DO $$
DECLARE
  v_salt TEXT;
  v_hash TEXT;
BEGIN
  v_salt := generate_salt();
  v_hash := hash_password('ChangeMeNow!2026', v_salt);

  INSERT INTO super_admins (username, password_hash, password_salt, totp_enabled, is_active)
  VALUES ('admin', v_hash, v_salt, false, true)
  ON CONFLICT (username) DO NOTHING;

  RAISE NOTICE 'Default super admin created. Username: admin, Password: ChangeMeNow!2026';
  RAISE NOTICE 'IMPORTANT: Change this password immediately after first login!';
END $$;
