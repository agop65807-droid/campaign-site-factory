const factoryApi = createApi('factory_token', '/api/factory');

const factoryState = {
  authorized: false,
  user: null,
  tenants: [],
  logs: [],
  selectedTenant: null,
  selectedTenantDomains: [],
  selectedTenantJobs: [],
  activeWizardStep: 1,
  currentProvisionJobId: null,
  setupToken2FA: null
};

function resetLoginState() {
  const loginForm = $('loginForm');
  const enrollSection = $('enrollTotpSection');
  const totpSection = $('totpSection');
  const loginError = $('loginError');
  const enrollCode = $('enrollVerifyCode');
  const loginTotp = $('loginTotp');
  const enrollSecret = $('enrollSecret');
  const enrollQr = $('enrollQr');

  loginForm?.classList.remove('hidden');
  enrollSection?.classList.add('hidden');
  totpSection?.classList.add('hidden');
  loginError?.classList.add('hidden');
  enrollCode && (enrollCode.value = '');
  loginTotp && (loginTotp.value = '');
  enrollSecret && (enrollSecret.textContent = '');
  enrollQr?.removeAttribute('src');
  factoryState.setupToken2FA = null;
}

function showLoginView() {
  document.body.classList.remove('factory-authenticated');
  document.body.classList.add('factory-login');
  $('loginView').classList.remove('hidden');
  $('appView').classList.add('hidden');
  resetLoginState();
}

function enterFactoryApp() {
  // Set the auth state before changing either view so CSS cannot render both
  // the enrollment card and the dashboard during a transition.
  document.body.classList.add('factory-authenticated');
  document.body.classList.remove('factory-login');
  $('loginView').classList.add('hidden');
  $('appView').classList.remove('hidden');
  resetLoginState();
  showSection('dashboard');
}

async function initFactory() {
  bindEvents();
  if (!factoryApi.getToken()) { showLoginView(); return; }
  try {
    const data = await factoryApi.get('/me');
    if (data.success) { factoryState.user = data.admin; enterFactoryApp(); }
  } catch (e) { factoryApi.setToken(null); showLoginView(); }
}

async function handleLogin(e) {
  e.preventDefault();
  const username = $('loginUsername').value.trim();
  const password = $('loginPassword').value;
  const totp = $('loginTotp').value.trim();
  const errEl = $('loginError');
  errEl.classList.add('hidden');
  const btn = $('loginBtn');
  btn.disabled = true;
  btn.textContent = 'جاري التحقق...';
  try {
    const payload = { username, password };
    if (totp) payload.totp_code = totp;
    const data = await factoryApi.post('/auth/login', payload, { auth: false });
    if (data.totp_enrollment_required) {
      factoryState.setupToken2FA = data.setup_token;
      $('enrollSecret').textContent = data.secret;
      $('enrollQr').src = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(data.otpauth_uri);
      $('loginForm').classList.add('hidden');
      $('enrollTotpSection').classList.remove('hidden');
      showToast('يرجى تفعيل التحقق الثنائي', 'info');
      return;
    }
    if (data.totp_required) {
      $('totpSection').classList.remove('hidden');
      $('loginTotp').setAttribute('required', 'required');
      showToast('رمز 2FA مطلوب', 'warning');
      return;
    }
    factoryApi.setToken(data.token);
    factoryState.user = data.admin;
    enterFactoryApp();
    showToast('مرحباً', 'success');
  } catch (err) {
    errEl.textContent = err.message || 'فشل تسجيل الدخول';
    errEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.textContent = 'تسجيل الدخول';
  }
}

async function handleVerifyEnroll() {
  const code = $('enrollVerifyCode').value.trim();
  if (!code || code.length !== 6) { showToast('أدخل كود 6 أرقام', 'error'); return; }
  const btn = $('enrollVerifyBtn');
  btn.disabled = true;
  try {
    const data = await factoryApi.post('/auth/totp/verify-setup', { setup_token: factoryState.setupToken2FA, code }, { auth: false });
    factoryApi.setToken(data.token);
    enterFactoryApp();
    showToast('تم تفعيل 2FA', 'success');
  } catch (e) { showToast(e.message, 'error'); }
  finally { btn.disabled = false; }
}

function handleLogout() { factoryApi.setToken(null); location.reload(); }

function showSection(sectionName) {
  document.querySelectorAll('.section').forEach(s => s.classList.add('hidden'));
  const target = $('sec-' + sectionName);
  if (target) target.classList.remove('hidden');
  document.querySelectorAll('.nav-item[data-section]').forEach(item => {
    item.classList.toggle('active', item.dataset.section === sectionName);
  });
  const loaders = { dashboard: loadDashboardData, tenants: loadTenants, wizard: initWizardForm, logs: loadAuditLogs };
  if (loaders[sectionName]) loaders[sectionName]();
}

async function loadDashboardData() {
  const container = $('dashboardCards');
  if (!container) return;
  container.innerHTML = Array(4).fill('<div class="card skeleton" style="height:90px"></div>').join('');
  try {
    const data = await factoryApi.get('/tenants');
    const tenants = data.tenants || [];
    const active = tenants.filter(t => t.status === 'active').length;
    const creating = tenants.filter(t => t.status === 'creating').length;
    const failed = tenants.filter(t => t.status === 'failed' || t.status === 'deleting').length;
    container.innerHTML = '<div class="card stat-card"><div class="stat-value text-primary">' + tenants.length + '</div><div class="stat-label">إجمالي الجهات</div></div><div class="card stat-card"><div class="stat-value text-success">' + active + '</div><div class="stat-label">نشطة</div></div><div class="card stat-card"><div class="stat-value text-warning">' + creating + '</div><div class="stat-label">قيد الإنشاء</div></div><div class="card stat-card"><div class="stat-value text-danger">' + failed + '</div><div class="stat-label">فاشلة</div></div>';
    renderRecentTenants(tenants.slice(0, 5));
  } catch (e) { showToast('تعذر تحميل البيانات', 'error'); }
}

function renderRecentTenants(tenants) {
  const tbody = $('recentTenantsTbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (!tenants.length) { tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">لا توجد جهات</td></tr>'; return; }
  tenants.forEach(t => {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td class="font-bold">' + esc(t.org_name) + '</td><td><span class="kbd text-xs" dir="ltr">' + esc(t.primary_domain || t.slug) + '</span></td><td><span class="badge ' + (t.status === 'active' ? 'badge-success' : 'badge-warning') + '">' + esc(t.status) + '</span></td><td class="text-xs text-muted">' + fmtDate(t.created_at) + '</td>';
    tbody.appendChild(tr);
  });
}

async function loadTenants() {
  const tbody = $('tenantsTbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="5"><div class="skeleton" style="height:50px"></div></td></tr>';
  try {
    const data = await factoryApi.get('/tenants');
    factoryState.tenants = data.tenants || [];
    renderTenantsList();
  } catch (e) { showToast('تعذر تحميل الجهات', 'error'); }
}

function renderTenantsList() {
  const tbody = $('tenantsTbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (!factoryState.tenants.length) { tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">لا توجد جهات</td></tr>'; return; }
  factoryState.tenants.forEach(t => {
    const tr = document.createElement('tr');
    const siteBase = t.primary_domain ? `https://${t.primary_domain}` : (t.vercel_url || 'https://' + t.slug + '.vercel.app');
    const campaignUrl = siteBase + '/campaign';
    const adminUrl = siteBase + '/admin';
    tr.innerHTML = '<td><span class="font-bold">' + esc(t.org_name) + '</span></td><td><span class="kbd text-xs" dir="ltr">' + esc(t.slug) + '</span></td><td><span class="badge ' + (t.status === 'active' ? 'badge-success' : t.status === 'suspended' ? 'badge-danger' : 'badge-warning') + '">' + esc(t.status) + '</span></td><td><div class="flex gap-2"><a class="btn btn-ghost btn-sm" href="' + campaignUrl + '" target="_blank">رئيسية</a><a class="btn btn-ghost btn-sm" href="' + adminUrl + '" target="_blank">إدارة</a></div></td><td><button class="btn btn-primary btn-sm" data-act="view" data-id="' + t.id + '">التفاصيل</button></td>';
    tr.querySelector('[data-act="view"]').addEventListener('click', () => viewTenantDetail(t.id));
    tbody.appendChild(tr);
  });
}

async function viewTenantDetail(id) {
  try {
    const data = await factoryApi.get('/tenants/' + id);
    const tenant = data.tenant;
    factoryState.selectedTenant = tenant;
    factoryState.selectedTenantDomains = data.domains || [];
    factoryState.selectedTenantJobs = data.jobs || [];
    document.querySelectorAll('.section').forEach(s => s.classList.add('hidden'));
    $('sec-tenant-detail').classList.remove('hidden');
    $('dtOrgName').textContent = 'إدارة: ' + tenant.org_name;
    const siteBase = tenant.primary_domain ? `https://${tenant.primary_domain}` : (tenant.vercel_url || 'https://' + tenant.slug + '.vercel.app');
    const campaignUrl = siteBase + '/campaign';
    const adminUrl = siteBase + '/admin';
    $('dtSiteUrl').href = campaignUrl;
    $('dtSiteUrl').textContent = campaignUrl;
    $('dtAdminUrl').href = adminUrl;
    $('dtAdminUrl').textContent = adminUrl;
    const statusBadge = $('dtStatusBadge');
    statusBadge.textContent = tenant.status;
    statusBadge.className = 'badge ' + (tenant.status === 'active' ? 'badge-success' : 'badge-warning');
    $('dtBtnSuspend').textContent = tenant.status === 'suspended' ? 'تفعيل' : 'تعطيل';
    $('dtBtnSuspend').onclick = () => toggleTenantSuspend(tenant);
    $('dtBtnDelete').onclick = () => confirmAction('حذف ' + tenant.org_name + '؟', () => deleteTenant(tenant.id));
    renderTenantDomains();
    renderTenantProvisionJobs();
  } catch (e) { showToast('تعذر تحميل التفاصيل', 'error'); }
}

async function toggleTenantSuspend(tenant) {
  const nextStatus = tenant.status === 'suspended' ? 'active' : 'suspended';
  try {
    await factoryApi.put('/tenants/' + tenant.id, { status: nextStatus });
    showToast('تم التحديث', 'success');
    viewTenantDetail(tenant.id);
  } catch (e) { showToast(e.message, 'error'); }
}

async function deleteTenant(id) {
  try { await factoryApi.del('/tenants/' + id); showToast('تم الحذف', 'success'); showSection('tenants'); }
  catch (e) { showToast(e.message, 'error'); }
}

function renderTenantDomains() {
  const tbody = $('domainsTbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (!factoryState.selectedTenantDomains.length) { tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">لا توجد نطاقات</td></tr>'; return; }
  factoryState.selectedTenantDomains.forEach(d => {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td class="font-bold" dir="ltr" style="text-align:right">' + esc(d.hostname) + '</td><td><span class="badge ' + (d.domain_type === 'custom' ? 'badge-info' : 'badge-muted') + '">' + esc(d.domain_type) + '</span></td><td><span class="badge ' + (d.status === 'verified' ? 'badge-success' : 'badge-warning') + '">' + esc(d.status) + '</span></td><td>' + (d.is_primary ? 'رئيسي' : '—') + '</td><td><button class="btn btn-danger btn-sm" data-dact="remove" data-id="' + d.id + '">حذف</button></td>';
    tr.querySelector('[data-dact="remove"]').addEventListener('click', () => confirmAction('حذف النطاق؟', () => removeDomain(d.id)));
    tbody.appendChild(tr);
  });
}

async function addHostname() {
  const hostname = $('newHostname').value.trim();
  if (!hostname) { showToast('أدخل النطاق', 'error'); return; }
  const btn = $('btnAddHostname');
  btn.disabled = true;
  try {
    const data = await factoryApi.post('/tenants/' + factoryState.selectedTenant.id + '/domains', { hostname, setPrimary: true });
    $('newHostname').value = '';
    const recWrap = $('dnsRecommendation');
    const recData = $('dnsRecData');
    if (recWrap) recWrap.classList.remove('hidden');
    if (recData) recData.textContent = JSON.stringify(data.dns.recommended, null, 2);
    showToast('تمت إضافة النطاق', 'success');
    viewTenantDetail(factoryState.selectedTenant.id);
  } catch (e) { showToast(e.message, 'error'); }
  finally { btn.disabled = false; }
}

async function removeDomain(domainId) {
  try { await factoryApi.del('/tenants/' + factoryState.selectedTenant.id + '/domains/' + domainId); showToast('تم الحذف', 'success'); viewTenantDetail(factoryState.selectedTenant.id); }
  catch (e) { showToast(e.message, 'error'); }
}

function renderTenantProvisionJobs() {
  const tbody = $('jobsTbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (!factoryState.selectedTenantJobs.length) { tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">لا يوجد سجل</td></tr>'; return; }
  factoryState.selectedTenantJobs.forEach(j => {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td class="font-semibold text-secondary">' + esc(j.step) + '</td><td><span class="badge ' + (j.status === 'completed' ? 'badge-success' : j.status === 'failed' ? 'badge-danger' : 'badge-warning') + '">' + esc(j.status) + '</span></td><td><div class="flex items-center gap-2"><div class="progress-track" style="width:80px;height:6px"><div class="progress-fill" style="width:' + j.progress + '%"></div></div><span class="text-xs">' + j.progress + '%</span></div></td><td class="text-xs text-muted">' + fmtDate(j.completed_at || j.started_at) + '</td>';
    tbody.appendChild(tr);
  });
}

function initWizardForm() {
  factoryState.activeWizardStep = 1;
  wizardGo(1);
  if ($('wizardForm')) $('wizardForm').reset();
  if ($('wizardProvisioningLogs')) $('wizardProvisioningLogs').classList.add('hidden');
  if ($('wizardButtons')) $('wizardButtons').classList.remove('hidden');
  if ($('wizardError')) $('wizardError').classList.add('hidden');
}

function wizardGo(step) {
  factoryState.activeWizardStep = step;
  document.querySelectorAll('.wizard-step').forEach((ws, i) => {
    ws.classList.toggle('active', i + 1 === step);
    ws.classList.toggle('done', i + 1 < step);
  });
  document.querySelectorAll('.wizard-panel').forEach((wp, i) => {
    wp.classList.toggle('active', i + 1 === step);
  });
  if (step === 4) {
    if ($('cOrgName')) $('cOrgName').textContent = $('wName').value;
    if ($('cSlug')) $('cSlug').textContent = $('wSlug').value || generateSlug($('wName').value);
    if ($('cAdminUser')) $('cAdminUser').textContent = $('wAdminUser').value;
  }
}

function generateRandomPass() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^*';
  let str = '';
  for (let i = 0; i < 12; i++) str += chars.charAt(Math.floor(Math.random() * chars.length));
  if ($('wAdminPass')) {
    $('wAdminPass').value = str;
    $('wAdminPass').type = 'text';
  }
  showToast('تم توليد كلمة مرور', 'success');
}

function generateSlug(text) {
  return String(text || '').toLowerCase().replace(/[^\w\s-]/g, '').replace(/\s+/g, '-').replace(/-+/g, '-').trim().substring(0, 50);
}

async function launchTenantFactory() {
  const orgName = $('wName').value.trim();
  const slug = $('wSlug').value.trim() || generateSlug(orgName);
  const adminUsername = $('wAdminUser').value.trim();
  const adminPassword = $('wAdminPass').value;
  if (!orgName || !adminUsername || !adminPassword) { showToast('املأ الحقول المطلوبة', 'error'); return; }
  if ($('wizardError')) $('wizardError').classList.add('hidden');
  if ($('wizardButtons')) $('wizardButtons').classList.add('hidden');
  if ($('wizardProvisioningLogs')) $('wizardProvisioningLogs').classList.remove('hidden');
  try {
    const tenantPayload = {
      orgName, slug, description: $('wDesc').value.trim(), hashtag: $('wHashtag').value.trim(),
      primaryColor: $('wColorPrimaryHex').value, secondaryColor: $('wColorSecondaryHex').value,
      themeMode: $('wTheme').value, logoUrl: $('wLogo').value,
      enabledSharePlatforms: [$('wPlatX').checked ? 'x' : null, $('wPlatWa').checked ? 'whatsapp' : null, $('wPlatFb').checked ? 'facebook' : null, $('wPlatTg').checked ? 'telegram' : null].filter(Boolean)
    };
    const res = await factoryApi.post('/tenants', tenantPayload);
    const tenant = res.tenant;
    const initJob = await factoryApi.post('/provision/start', { tenantId: tenant.id, adminUsername, adminPassword });
    factoryState.currentProvisionJobId = initJob.jobId;
    driveProvisioningStep(tenant, initJob.jobId, adminUsername, adminPassword);
  } catch (e) { showWizardError(e.message); }
}

async function driveProvisioningStep(tenant, jobId, adminUsername, adminPassword) {
  try {
    const res = await factoryApi.post('/provision/step', { jobId, adminUsername, adminPassword });
    updateWizardProgress(res.step, res.progress);
    if (res.done) {
      if (res.success) { showToast('تم إنشاء الموقع بنجاح', 'success'); setTimeout(() => { showSection('tenants'); }, 3000); }
      else { showWizardError(res.error || 'فشل التزويد'); }
    } else { setTimeout(() => { driveProvisioningStep(tenant, jobId, adminUsername, adminPassword); }, 1000); }
  } catch (e) { showWizardError(e.message); }
}

function updateWizardProgress(step, progress) {
  const labels = {
    'init': 'بدء التهيئة...', 'create_supabase': 'إنشاء قاعدة البيانات...',
    'run_migration': 'بناء الجداول والمشرف...', 'create_vercel': 'ربط المشروع على Vercel...',
    'set_env_vars': 'تعيين متغيرات البيئة...', 'deploy': 'نشر الموقع...',
    'add_domains': 'إعداد النطاقات...', 'health_check': 'فحص الصحة...',
    'completed': 'اكتمل التزويد بنجاح!'
  };
  if ($('wizardStepLabel')) $('wizardStepLabel').textContent = labels[step] || 'جاري المعالجة...';
  if ($('wizardProgressPct')) $('wizardProgressPct').textContent = progress + '%';
  if ($('wizardProgressFill')) $('wizardProgressFill').style.width = progress + '%';
  const list = $('wizardStepsStatus');
  if (list) {
    const dot = document.createElement('div');
    dot.className = 'step-progress';
    dot.innerHTML = '<div class="step-dot done">✓</div><span>' + (labels[step] || step) + ' (' + progress + '%)</span>';
    list.appendChild(dot);
  }
}

function showWizardError(msg) {
  if ($('wizardError')) {
    $('wizardError').textContent = 'خطأ: ' + msg;
    $('wizardError').classList.remove('hidden');
  }
  if ($('wizardButtons')) $('wizardButtons').classList.remove('hidden');
}

async function loadAuditLogs() {
  const tbody = $('logsTbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6"><div class="skeleton" style="height:45px"></div></td></tr>';
  try {
    const data = await factoryApi.get('/logs');
    const logs = data.logs || [];
    tbody.innerHTML = '';
    if (!logs.length) { tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">لا يوجد سجل</td></tr>'; return; }
    logs.forEach(l => {
      const tenant = factoryState.tenants.find(t => t.id === l.tenant_id);
      const tr = document.createElement('tr');
      tr.innerHTML = '<td><span class="font-bold text-secondary">مشرف</span></td><td>' + (tenant ? '<span class="badge badge-info">' + esc(tenant.org_name) + '</span>' : '—') + '</td><td><strong class="text-primary">' + esc(l.action_type) + '</strong></td><td class="truncate" style="max-width:300px">' + esc(JSON.stringify(l.details)) + '</td><td><span class="kbd text-xs">' + esc(l.ip_address || '') + '</span></td><td class="text-xs text-muted">' + fmtDate(l.created_at) + '</td>';
      tbody.appendChild(tr);
    });
  } catch (e) { showToast('تعذر تحميل السجل', 'error'); }
}

function bindEvents() {
  if ($('loginForm')) $('loginForm').addEventListener('submit', handleLogin);
  if ($('enrollVerifyBtn')) $('enrollVerifyBtn').addEventListener('click', handleVerifyEnroll);
  if ($('logoutBtn')) $('logoutBtn').addEventListener('click', handleLogout);
  if ($('btnAddHostname')) $('btnAddHostname').addEventListener('click', addHostname);
  if ($('btnLaunchFactory')) $('btnLaunchFactory').addEventListener('click', launchTenantFactory);
  document.querySelectorAll('.nav-item[data-section]').forEach(btn => {
    btn.addEventListener('click', () => showSection(btn.dataset.section));
  });
  if ($('wColorPrimary') && $('wColorPrimaryHex')) {
    $('wColorPrimary').addEventListener('input', (e) => { $('wColorPrimaryHex').value = e.target.value; });
    $('wColorPrimaryHex').addEventListener('input', (e) => { if (/^#[0-9A-Fa-f]{6}$/.test(e.target.value)) $('wColorPrimary').value = e.target.value; });
  }
  if ($('wColorSecondary') && $('wColorSecondaryHex')) {
    $('wColorSecondary').addEventListener('input', (e) => { $('wColorSecondaryHex').value = e.target.value; });
    $('wColorSecondaryHex').addEventListener('input', (e) => { if (/^#[0-9A-Fa-f]{6}$/.test(e.target.value)) $('wColorSecondary').value = e.target.value; });
  }

  const btnBack = $('btnBackToTenants');
  if (btnBack) btnBack.addEventListener('click', () => showSection('tenants'));

  const btnGenPass = $('btnGenPass');
  if (btnGenPass) btnGenPass.addEventListener('click', generateRandomPass);

  document.querySelectorAll('[data-wizard]').forEach(btn => {
    btn.addEventListener('click', () => wizardGo(parseInt(btn.dataset.wizard, 10)));
  });
}

document.addEventListener('DOMContentLoaded', initFactory);
