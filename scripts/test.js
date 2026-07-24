const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const rootDir = path.resolve(__dirname, '..');
let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✓ PASSED: ${message}`);
    passed++;
  } else {
    console.error(`  ✗ FAILED: ${message}`);
    failed++;
  }
}

console.log('==================================================');
console.log('Running Campaign Site Factory Quality & Safety Tests');
console.log('==================================================\n');

// 1. JavaScript Syntax Check
console.log('1. Checking JavaScript Syntax:');
const jsFiles = [
  'api/[...path].js',
  'api/factory/[...path].js',
  'api/config.css.js',
  'api/factory-router.js',
  'api/health.js',
  'api/manifest.js',
  'api/tenant-router.js',
  'assets/js/api.js',
  'assets/js/admin.js',
  'assets/js/factory.js',
  'assets/js/public.js',
  'assets/js/theme.js',
  'lib/crypto.js',
  'lib/domains.js',
  'lib/provisioning.js',
  'lib/rate-limit.js',
  'lib/supabase.js',
  'lib/supabase-mgmt.js',
  'lib/tenant-resolver.js',
  'lib/totp.js',
  'lib/validation.js',
  'lib/vercel.js',
  'scripts/dev-server.js',
  'scripts/lint.js'
];

for (const file of jsFiles) {
  const fullPath = path.join(rootDir, file);
  if (fs.existsSync(fullPath)) {
    try {
      execSync(`node --check "${fullPath}"`, { stdio: 'pipe' });
      assert(true, `Syntax check: ${file}`);
    } catch (e) {
      assert(false, `Syntax error in ${file}: ${e.message}`);
    }
  } else {
    assert(false, `File missing: ${file}`);
  }
}

// 2. CSS .hidden Override Check
console.log('\n2. Checking CSS .hidden Override Rules:');
const appCssSrc = fs.readFileSync(path.join(rootDir, 'src', 'styles', 'app.css'), 'utf8');
const appCssCompiled = fs.readFileSync(path.join(rootDir, 'assets', 'app.css'), 'utf8');

assert(appCssSrc.includes('.hidden { display: none !important; }'), 'src/styles/app.css has !important on .hidden');
assert(
  /\.hidden\s*\{\s*display\s*:\s*none\s*!important\s*\}/.test(appCssCompiled),
  'assets/app.css has !important on .hidden'
);

// 3. Static Assets Existence Check
console.log('\n3. Checking Static Assets:');
const faviconPath = path.join(rootDir, 'favicon.ico');
const logoPath = path.join(rootDir, 'logo-dark.png');
const xlsxPath = path.join(rootDir, 'assets', 'js', 'xlsx.full.min.js');
assert(fs.existsSync(faviconPath), 'favicon.ico exists');
assert(fs.existsSync(logoPath), 'logo-dark.png exists');
assert(fs.existsSync(xlsxPath), 'assets/js/xlsx.full.min.js exists');

const logo = fs.readFileSync(logoPath);
const favicon = fs.readFileSync(faviconPath);
const xlsx = fs.readFileSync(xlsxPath, 'utf8');
assert(
  logo.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) && logo.length > 1000,
  'logo-dark.png is a valid non-placeholder PNG'
);
assert(
  favicon.readUInt16LE(0) === 0 && favicon.readUInt16LE(2) === 1 && favicon.length > 1000,
  'favicon.ico is a valid non-placeholder icon'
);
assert(
  xlsx.length > 500000 && xlsx.includes('0.20.3') && !xlsx.includes('XLSX Light Shim'),
  'SheetJS full browser build is vendored locally'
);

// 4. SQL Migration Security Check
console.log('\n4. Checking SQL Security & Tenant Isolation:');
const factorySql = fs.readFileSync(path.join(rootDir, 'sql', 'factory', '01_migration.sql'), 'utf8');
const tenantSql = fs.readFileSync(path.join(rootDir, 'sql', 'tenant', '01_migration.sql'), 'utf8');
const securitySql = fs.readFileSync(path.join(rootDir, 'sql', 'security', '01_lockdown.sql'), 'utf8');

assert(factorySql.includes('revoke execute on all functions in schema public from public'), 'Factory SQL revokes public function execution');
assert(tenantSql.includes('revoke execute on all functions in schema public from public'), 'Tenant SQL revokes public function execution');
assert(tenantSql.includes('alter table campaigns add column if not exists tenant_id uuid'), 'Tenant SQL includes tenant_id on campaigns');
assert(tenantSql.includes('alter table tweets add column if not exists tenant_id uuid'), 'Tenant SQL includes tenant_id on tweets');
assert(tenantSql.includes('drop function if exists exec_sql'), 'Tenant SQL drops arbitrary exec_sql function');
assert(securitySql.includes("where schemaname = 'public'"), 'Security migration removes legacy public policies');
assert(securitySql.includes('force row level security'), 'Security migration forces RLS on exposed tables');
assert(securitySql.includes('revoke all privileges on all tables'), 'Security migration revokes direct public table access');

// 5. Tenant Resolver Module Test
console.log('\n5. Checking Tenant Resolver Module:');
try {
  const { resolveTenant } = require(path.join(rootDir, 'lib', 'tenant-resolver.js'));
  assert(typeof resolveTenant === 'function', 'resolveTenant exported as function');
} catch (e) {
  assert(false, `Failed to load tenant resolver: ${e.message}`);
}

// 6. Tenant Isolation Regression Checks
console.log('\n6. Checking Tenant Isolation Regressions:');
const tenantResolverSource = fs.readFileSync(path.join(rootDir, 'lib', 'tenant-resolver.js'), 'utf8');
const tenantApiSource = fs.readFileSync(path.join(rootDir, 'api', '[...path].js'), 'utf8');
assert(!tenantResolverSource.includes("x-tenant-id"), 'Tenant identity cannot be selected through X-Tenant-ID');
assert(!tenantResolverSource.includes("x-site-slug"), 'Tenant identity cannot be selected through X-Site-Slug');
assert(!tenantResolverSource.includes('defaultTenants'), 'Resolver does not fall back to an arbitrary active tenant');
assert(!tenantApiSource.includes('tenant_id.is.null'), 'Tenant-scoped queries do not include legacy NULL rows');
assert(!tenantApiSource.includes("'Access-Control-Allow-Origin': '*'"), 'Tenant API does not allow wildcard CORS');

// 7. Routing and Provisioning Regression Checks
console.log('\n7. Checking Routing and Provisioning Regressions:');
const vercelConfig = JSON.parse(fs.readFileSync(path.join(rootDir, 'vercel.json'), 'utf8'));
const rewrites = JSON.stringify(vercelConfig.rewrites || []);
const devServerSource = fs.readFileSync(path.join(rootDir, 'scripts', 'dev-server.js'), 'utf8');
const provisioningSource = fs.readFileSync(path.join(rootDir, 'lib', 'provisioning.js'), 'utf8');
const factorySource = fs.readFileSync(path.join(rootDir, 'assets', 'js', 'factory.js'), 'utf8');
assert(rewrites.includes('/api/factory/:path*'), 'Vercel rewrites nested factory API paths');
assert(rewrites.includes('/api/auth/:path*'), 'Vercel rewrites nested tenant auth paths');
assert(devServerSource.indexOf("pathname === '/api/health'") < devServerSource.indexOf("pathname.startsWith('/api')"), 'Dev server routes health before catch-all API');
assert(!provisioningSource.includes('healthy = true; // Non-blocking'), 'Provisioning health check fails closed on network errors');
assert((factorySource.match(/async function initFactory\(/g) || []).length === 1, 'Factory has one initFactory definition');
assert((factorySource.match(/async function handleLogin\(/g) || []).length === 1, 'Factory has one handleLogin definition');

// 8. Factory Wizard Validation Regressions
console.log('\n8. Checking Factory Wizard Validation Regressions:');
const { tenantCreateSchema } = require(path.join(rootDir, 'lib', 'validation.js'));
const blankOptionalUrls = tenantCreateSchema.safeParse({
  orgName: 'سلام',
  slug: 'ffff',
  logoUrl: '',
  faviconUrl: '',
  primaryColor: '#15803d',
  secondaryColor: '#d97706',
  themeMode: 'dark',
  enabledSharePlatforms: ['x']
});
assert(blankOptionalUrls.success, 'Factory tenant creation accepts blank optional logo URLs');
const malformedLogoUrl = tenantCreateSchema.safeParse({ orgName: 'سلام', logoUrl: 'not-a-url' });
assert(!malformedLogoUrl.success, 'Factory tenant creation still rejects malformed logo URLs');

console.log('\n==================================================');
console.log(`Test Results: ${passed} passed, ${failed} failed.`);
console.log('==================================================');

if (failed > 0) {
  process.exit(1);
}
