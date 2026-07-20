-- ============================================================
-- Default Super Admin — Randomly generated password
-- The password is printed ONCE via RAISE NOTICE
-- MUST change password on first login + enroll 2FA
-- ============================================================

do $$
declare
  v_salt text;
  v_hash text;
  v_plain_password text;
  v_bytes bytea;
  v_chars text[];
  v_len integer := 16;
  v_i integer;
  v_byte_val integer;
begin
  -- Generate a cryptographically secure random password (16 chars)
  v_chars := ARRAY['A','B','C','D','E','F','G','H','J','K','L','M','N','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','m','n','p','q','r','s','t','u','v','w','x','y','z','2','3','4','5','6','7','8','9','!','@','#','$','%','&','*'];
  v_bytes := gen_random_bytes(v_len);
  v_plain_password := '';
  for v_i in 0..v_len-1 loop
    v_byte_val := get_byte(v_bytes, v_i);
    v_plain_password := v_plain_password || v_chars[(v_byte_val % array_length(v_chars, 1)) + 1];
  end loop;

  v_salt := encode(gen_random_bytes(32), 'hex');
  v_hash := encode(
    pbkdf2(v_plain_password, decode(v_salt, 'hex'), 100000, 64, 'sha512'),
    'hex'
  );

  insert into super_admins (
    username,
    password_hash,
    password_salt,
    totp_enabled,
    must_enroll_totp,
    must_change_password,
    is_active
  )
  values (
    'admin',
    v_hash,
    v_salt,
    false,
    true,
    true,
    true
  )
  on conflict (username) do nothing;

  raise notice '============================================================';
  raise notice '  DEFAULT SUPER ADMIN CREATED SUCCESSFULLY';
  raise notice '  Username: admin';
  raise notice '  Temporary Password: %', v_plain_password;
  raise notice '  IMPORTANT: Change password + enroll 2FA on first login!';
  raise notice '============================================================';
end $$;
