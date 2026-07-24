// Mirrors hashPassword()/generateSalt()/timingSafeCompare() in the tenant
// template's api/[...path].js so main_admins rows we create during
// provisioning are verifiable by that same code, and so the factory's own
// super_admins table uses an equally strong scheme.

const crypto = require('crypto');

function generateSalt() {
  return crypto.randomBytes(32).toString('hex');
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

function timingSafeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); } catch { return false; }
}

function generateToken() {
  return crypto.randomBytes(48).toString('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/** Generates a strong random password for new tenant main-admin accounts (used once, shown only in the creation-result screen — see PRD §7b step 11). */
function generateStrongPassword(length = 16) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*';
  const bytes = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) out += alphabet[bytes[i] % alphabet.length];
  return out;
}

module.exports = { generateSalt, hashPassword, timingSafeCompare, generateToken, hashToken, generateStrongPassword };
