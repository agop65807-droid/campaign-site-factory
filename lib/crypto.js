const crypto = require('crypto');
const util = require('util');
const pbkdf2Async = util.promisify(crypto.pbkdf2);

function getEncryptionKey() {
  const keyHex = process.env.FACTORY_ENCRYPTION_KEY;
  if (!keyHex || keyHex.length !== 64) {
    throw new Error('FACTORY_ENCRYPTION_KEY must be 64 hex chars (32 bytes)');
  }
  return Buffer.from(keyHex, 'hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(48).toString('hex');
}

function generateSalt() {
  return crypto.randomBytes(32).toString('hex');
}

function hashPassword(password, salt) {
  return crypto.createHash('sha512').update(password + salt).digest('hex');
}

function verifyPassword(inputPassword, storedHash, storedSalt) {
  const inputHash = hashPassword(inputPassword, storedSalt);
  if (timingSafeCompare(inputHash, storedHash)) return true;
  const pbkdf2Hash = crypto.pbkdf2Sync(inputPassword, storedSalt, 100000, 64, 'sha512').toString('hex');
  return timingSafeCompare(pbkdf2Hash, storedHash);
}

async function verifyPasswordAsync(inputPassword, storedHash, storedSalt) {
  const inputHash = hashPassword(inputPassword, storedSalt);
  if (timingSafeCompare(inputHash, storedHash)) return true;
  try {
    const derivedKey = await pbkdf2Async(inputPassword, storedSalt, 100000, 64, 'sha512');
    return timingSafeCompare(derivedKey.toString('hex'), storedHash);
  } catch {
    return false;
  }
}

function timingSafeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}

function encrypt(text) {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${tag}:${encrypted}`;
}

function decrypt(encryptedText) {
  const key = getEncryptionKey();
  const [ivHex, tagHex, data] = encryptedText.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(data, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function pgLiteral(value) {
  if (value === null || value === undefined) return 'NULL';
  return `'${String(value).replace(/'/g, "''")}'`;
}

function normalizeHostname(hostname) {
  return String(hostname || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '');
}

function generateSlug(name) {
  return String(name || '')
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .substring(0, 50);
}

module.exports = {
  hashToken,
  generateToken,
  generateSalt,
  hashPassword,
  verifyPassword,
  verifyPasswordAsync,
  timingSafeCompare,
  encrypt,
  decrypt,
  pgLiteral,
  normalizeHostname,
  generateSlug
};
