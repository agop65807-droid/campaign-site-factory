// ============================================================================
// secrets_vault helpers — AES-256-GCM encryption for Vercel/Render master
// tokens (security §11 item 1).
//
// Set FACTORY_ENCRYPTION_KEY as a Vercel environment variable on the FACTORY
// project only (never on any tenant project) — a 32-byte key, either
// hex-encoded (64 hex chars, e.g. `openssl rand -hex 32`) or base64-encoded
// (both are auto-detected below). (FACTORY_MASTER_KEY also still works, as
// an older/alternate name for the same variable.)
//
// This key is the single point of failure the PRD flags in §11/§14 — treat
// it like a root credential: restrict who can view/edit it in Vercel's
// project settings, and rotate it (re-encrypting all rows) if you suspect
// exposure. If this key was ever pasted somewhere outside of Vercel's
// environment variable UI (a chat, a doc, a ticket), treat it as exposed
// and regenerate it before going live.
// ============================================================================

const crypto = require('crypto');

function getMasterKey() {
  const raw = process.env.FACTORY_ENCRYPTION_KEY || process.env.FACTORY_MASTER_KEY;
  if (!raw) throw new Error('FACTORY_ENCRYPTION_KEY is not set');

  const isHex64 = /^[0-9a-fA-F]{64}$/.test(raw.trim());
  const key = isHex64 ? Buffer.from(raw.trim(), 'hex') : Buffer.from(raw.trim(), 'base64');

  if (key.length !== 32) {
    throw new Error(
      `FACTORY_ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256) — got ${key.length}. ` +
      `Use a 64-char hex string (openssl rand -hex 32) or a base64 string that decodes to 32 bytes.`
    );
  }
  return key;
}

function encrypt(plaintext) {
  const key = getMasterKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${ciphertext.toString('hex')}`;
}

function decrypt(stored) {
  const key = getMasterKey();
  const [ivHex, tagHex, dataHex] = String(stored).split(':');
  if (!ivHex || !tagHex || !dataHex) throw new Error('Malformed secrets_vault value');
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(tagHex, 'hex');
  const ciphertext = Buffer.from(dataHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString('utf8');
}

// --- Store-backed helpers -----------------------------------------------
// `db` is the factory's own database client (the same one every route in
// api/[...path].js uses), passed in by the caller rather than imported here,
// to keep this module easy to unit test without a live DB connection.

async function getSecret(db, keyName) {
  const { data, error } = await db
    .from('secrets_vault')
    .select('encrypted_value')
    .eq('key_name', keyName)
    .single();
  if (error || !data) return null;
  return decrypt(data.encrypted_value);
}

async function setSecret(db, keyName, plaintextValue) {
  const encrypted_value = encrypt(plaintextValue);
  const { error } = await db
    .from('secrets_vault')
    .upsert({ key_name: keyName, encrypted_value, updated_at: new Date().toISOString() }, { onConflict: 'key_name' });
  if (error) throw new Error('Failed to store secret: ' + error.message);
  return true;
}

async function deleteSecret(db, keyName) {
  await db.from('secrets_vault').delete().eq('key_name', keyName);
}

// Well-known key names for the two master tokens (bootstrap these once via
// a one-off script or the dashboard's initial setup screen — see README).
const KEYS = {
  VERCEL_TOKEN: 'vercel_api_token',
  VERCEL_TEAM_ID: 'vercel_team_id',
  tenantMainAdminPasswordOneTime: (tenantId) => `tenant:${tenantId}:main_admin_password_onetime`
};

module.exports = { encrypt, decrypt, getSecret, setSecret, deleteSecret, KEYS };
