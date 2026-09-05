// ============================================================================
// Minimal RFC 6238 TOTP implementation — no external dependency, so it works
// in a Vercel serverless function without extra install steps. Compatible
// with Google Authenticator / Authy / 1Password etc.
//
// Used for the mandatory 2FA on super_admins (security §11 item 3).
// ============================================================================

const crypto = require('crypto');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function generateSecret(bytes = 20) {
  const buf = crypto.randomBytes(bytes);
  return base32Encode(buf);
}

function base32Encode(buffer) {
  let bits = '';
  for (const byte of buffer) bits += byte.toString(2).padStart(8, '0');
  let output = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    output += BASE32_ALPHABET[parseInt(bits.substring(i, i + 5), 2)];
  }
  const remainder = bits.length % 5;
  if (remainder !== 0) {
    const lastChunk = bits.substring(bits.length - remainder).padEnd(5, '0');
    output += BASE32_ALPHABET[parseInt(lastChunk, 2)];
  }
  return output;
}

function base32Decode(encoded) {
  const clean = encoded.toUpperCase().replace(/=+$/, '').replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const char of clean) {
    const val = BASE32_ALPHABET.indexOf(char);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function hotp(secretBuffer, counter, digits = 6) {
  const counterBuffer = Buffer.alloc(8);
  // Write as a 64-bit big-endian integer (counter fits in the low 32 bits for our purposes).
  counterBuffer.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuffer.writeUInt32BE(counter % 0x100000000, 4);

  const hmac = crypto.createHmac('sha1', secretBuffer).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode = ((hmac[offset] & 0x7f) << 24)
    | ((hmac[offset + 1] & 0xff) << 16)
    | ((hmac[offset + 2] & 0xff) << 8)
    | (hmac[offset + 3] & 0xff);
  const code = binCode % (10 ** digits);
  return String(code).padStart(digits, '0');
}

function generateTotp(base32Secret, { step = 30, digits = 6, at = Date.now() } = {}) {
  const counter = Math.floor(at / 1000 / step);
  return hotp(base32Decode(base32Secret), counter, digits);
}

// Verifies a submitted code, allowing +/- 1 time step of clock drift.
function verifyTotp(base32Secret, submittedCode, { step = 30, digits = 6, window = 1, at = Date.now() } = {}) {
  if (!submittedCode || !/^\d+$/.test(String(submittedCode))) return false;
  const counter = Math.floor(at / 1000 / step);
  const secretBuffer = base32Decode(base32Secret);
  for (let errorWindow = -window; errorWindow <= window; errorWindow++) {
    const candidate = hotp(secretBuffer, counter + errorWindow, digits);
    if (timingSafeEqualStr(candidate, String(submittedCode).padStart(digits, '0'))) return true;
  }
  return false;
}

function timingSafeEqualStr(a, b) {
  if (a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); } catch { return false; }
}

function buildOtpauthUrl({ secret, accountName, issuer = 'Campaign Site Factory' }) {
  const params = new URLSearchParams({ secret, issuer, algorithm: 'SHA1', digits: '6', period: '30' });
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}?${params.toString()}`;
}

module.exports = { generateSecret, generateTotp, verifyTotp, buildOtpauthUrl, base32Encode, base32Decode };
