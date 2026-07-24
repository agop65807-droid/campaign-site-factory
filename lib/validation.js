const { z } = require('zod');

const hexColor = z.string().regex(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
const platformEnum = z.enum(['x', 'whatsapp', 'facebook', 'telegram', 'native']);
const optionalUrl = z.preprocess(
  (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
  z.string().url().max(500).optional()
);

const loginSchema = z.object({
  username: z.string().min(1).max(100),
  password: z.string().min(6).max(200),
  totp_code: z.string().length(6).optional()
});

const tenantCreateSchema = z.object({
  orgName: z.string().min(2).max(120),
  slug: z.string().min(2).max(60).regex(/^[a-z0-9-]+$/).optional(),
  description: z.string().max(500).optional(),
  hashtag: z.string().max(120).optional(),
  primaryColor: hexColor.optional(),
  secondaryColor: hexColor.optional(),
  themeMode: z.enum(['dark', 'light']).optional(),
  enabledSharePlatforms: z.array(platformEnum).min(1).max(5).optional(),
  logoUrl: optionalUrl,
  faviconUrl: optionalUrl,
  adminUsername: z.string().min(3).max(60).regex(/^[a-zA-Z0-9_.-]+$/).optional(),
  adminPassword: z.string().min(10).max(200).optional()
});

const tenantUpdateSchema = z.object({
  orgName: z.string().min(2).max(120).optional(),
  description: z.string().max(500).optional(),
  hashtag: z.string().max(120).optional(),
  primaryColor: hexColor.optional(),
  secondaryColor: hexColor.optional(),
  themeMode: z.enum(['dark', 'light']).optional(),
  enabledSharePlatforms: z.array(platformEnum).min(1).max(5).optional(),
  logoUrl: optionalUrl,
  faviconUrl: optionalUrl,
  status: z.enum(['active', 'suspended']).optional()
});

const domainSchema = z.object({
  hostname: z.string().min(4).max(253),
  setPrimary: z.boolean().optional()
});

const identitySchema = z.object({
  orgName: z.string().min(2).max(120).optional(),
  hashtag: z.string().max(120).optional(),
  logoUrl: optionalUrl,
  faviconUrl: optionalUrl,
  primaryColor: hexColor.optional(),
  secondaryColor: hexColor.optional(),
  themeMode: z.enum(['dark', 'light']).optional(),
  enabledSharePlatforms: z.array(platformEnum).min(1).max(5).optional(),
  metaTitle: z.string().max(200).optional(),
  metaDescription: z.string().max(400).optional()
});

module.exports = {
  loginSchema,
  tenantCreateSchema,
  tenantUpdateSchema,
  domainSchema,
  identitySchema
};
