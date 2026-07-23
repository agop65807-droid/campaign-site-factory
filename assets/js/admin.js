const api = createApi('admin_token');

const state = {
  user: null,
  config: {},
  campaigns: [],
  currentCampaignId: null,
  tweets: [],
  subAdmins: [],
  invites: [],
  editingCampaignId: null,
  editingTweetId: null,
  editingSubAdminId: null,
  importRows: [],
  pendingMustChange: false
};

const $ = (id) => document.getElementById(id);

function hasPerm(perm) {
  if (!state.user) return false;
  if (state.user.adminType === 'main') return true;
  return !!(state.user.permissions && state.user.permissions[perm]);
}

function showSection(name) {
  document.querySelectorAll('.section').forEach(s => s.classList.add('hidden'));
  const sec = $('sec-' + name);
  if (sec) sec.classList.remove('hidden');
  document.querySelectorAll('.nav-item[data-section]').forEach(n => {
    n.classList.toggle('active', n.dataset.section === name);
  });
  const loaders = {
    campaigns: loadCampaigns,
    tweets: loadTweetsSection,
    admins: loadSubAdmins,
    invites: loadInvites,
    stats: loadAnalytics,
    reports: loadReportsSection
  };
  if (loaders[name]) loaders[name]();
}

function applyPermissions() {
  document.querySelectorAll('[data-perm]').forEach(el => {
    if (!hasPerm(el.dataset.perm)) el.classList.add('hidden');
    else el.classList.remove('hidden');
  });
}

function confirmAction(message, onOk) {
  $('confirmText').textContent = message;
  const btn = $('confirmOkBtn');
  const clone = btn.cloneNode(true);
  btn.parentNode.replaceChild(clone, btn);
  clone.addEventListener('click', () => { closeModal('confirmModal'); onOk(); });
  openModal('confirmModal');
}

async function init() {
  document.addEventListener('site:ready', (e) => {
    state.config = e.detail || {};
    if (state.config.orgName) {
      $('loginOrgName').textContent = state.config.orgName;
      $('brandOrg').textContent = state.config.orgName;
    }
    if (state.config.logoUrl) {
      $('loginLogo').src = state.config.logoUrl;
      $('brandLogo').src = state.config.logoUrl;
    }
  });
  bindEvents();
  if (!api.getToken()) return;
  try {
    const data = await api.get('/api/me');
    if (data.success) enterApp(data.user);
  } catch (e) { api.setToken(null); }
}

function enterApp(user) {
  state.user = user;
  $('loginView').classList.add('hidden');
  $('appView').classList.remove('hidden');
  $('userName').textContent = user.name || 'المشرف';
  $('userType').textContent = user.adminType === 'main' ? 'مشرف رئيسي' : 'مشرف فرعي';
  applyPermissions();
  showSection(hasPerm('canCreateCampaign') ? 'campaigns' : 'tweets');
}

async function handleLogin(e) {
  e.preventDefault();
  const username = $('loginUsername').value.trim();
  const password = $('loginPassword').value;
  $('loginError').classList.add('hidden');
  $('loginBtn').disabled = true;
  $('loginBtnText').textContent = 'جاري التحقق...';
  try {
    const data = await api.post('/api/auth', { username, password }, { auth: false });
    api.setToken(data.token);
    const me = await api.get('/api/me');
    state.user = me.user;
    if (data.mustChangePassword) {
      state.pendingMustChange = true;
      enterApp(me.user);
      openModal('changePasswordModal');
    } else {
      enterApp(me.user);
      showToast('مرحباً ' + (me.user.name || ''), 'success');
    }
  } catch (err) {
    $('loginError').textContent = err.message || 'فشل تسجيل الدخول';
    $('loginError').classList.remove('hidden');
  } finally {
    $('loginBtn').disabled = false;
    $('loginBtnText').textContent = 'تسجيل الدخول';
  }
}

async function handleLogout() {
  try { await api.post('/api/logout', {}); } catch (e) {}
  api.setToken(null);
  state.user = null;
  $('appView').classList.add('hidden');
  $('loginView').classList.remove('hidden');
}

async function handleChangePassword() {
  const oldPass = $('cpOld').value;
  const newPass = $('cpNew').value;
  const confirmPass = $('cpConfirm').value;
  const errEl = $('cpError');
  errEl.classList.add('hidden');
  if (newPass.length < 10) { errEl.textContent = 'كلمة المرور الجديدة يجب أن تكون 10 أحرف على الأقل'; errEl.classList.remove('hidden'); return; }
  if (newPass !== confirmPass) { errEl.textContent = 'كلمتا المرور غير متطابقتين'; errEl.classList.remove('hidden'); return; }
  try {
    await api.post('/api/auth/change-password', { oldPassword: oldPass, newPassword: newPass });
    state.pendingMustChange = false;
    closeModal('changePasswordModal');
    showToast('تم تغيير كلمة المرور', 'success');
  } catch (err) {
    errEl.textContent = err.message || 'فشل تغيير كلمة المرور';
    errEl.classList.remove('hidden');
  }
}

async function loadCampaigns() {
  const grid = $('campaignsGrid');
  grid.innerHTML = '<div class="card skeleton" style="height:120px"></div>';
  try {
    const data = await api.get('/api/campaign');
    state.campaigns = data.campaigns || (data.campaign && data.campaign.id ? [data.campaign] : []);
    renderCampaigns();
    populateCampaignSelects();
  } catch (err) {
    grid.innerHTML = '<div class="card empty-state"><p>' + esc(err.message) + '</p></div>';
  }
}

function renderCampaigns() {
  const grid = $('campaignsGrid');
  grid.innerHTML = '';
  if (!state.campaigns.length) {
    grid.innerHTML = '<div class="card empty-state" style="grid-column:1/-1"><div class="icon">📢</div><p>لا توجد حملات</p></div>';
    return;
  }
  state.campaigns.forEach(c => {
    const card = document.createElement('div');
    card.className = 'card tweet-card';
    card.innerHTML = `
      <div class="flex items-center justify-between gap-2">
        <h3 class="font-bold text-lg truncate">${esc(c.name)}</h3>
        ${c.is_active ? '<span class="badge badge-success">نشطة</span>' : '<span class="badge badge-muted">معطلة</span>'}
      </div>
      ${c.description ? '<p class="text-sm text-muted mt-2">' + esc(c.description).substring(0, 100) + '</p>' : ''}
      <div class="flex gap-2 mt-3 text-xs text-muted flex-wrap">
        <span>${esc(fmtDate(c.target_time))}</span>
        ${c.hashtag ? '<span class="badge badge-info">' + esc(c.hashtag) + '</span>' : ''}
      </div>
      <div class="flex gap-2 mt-4">
        <button class="btn btn-primary btn-sm" data-act="open-tweets" data-id="${c.id}">التغريدات</button>
        ${hasPerm('canEditCampaign') ? '<button class="btn btn-ghost btn-sm" data-act="edit-campaign" data-id="' + c.id + '">تعديل</button>' : ''}
        ${hasPerm('canDeleteCampaign') ? '<button class="btn btn-danger btn-sm" data-act="del-campaign" data-id="' + c.id + '">حذف</button>' : ''}
      </div>
    `;
    grid.appendChild(card);
  });
  grid.querySelectorAll('[data-act]').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = parseInt(btn.dataset.id, 10);
      if (btn.dataset.act === 'open-tweets') { state.currentCampaignId = id; showSection('tweets'); }
      if (btn.dataset.act === 'edit-campaign') openCampaignModal(id);
      if (btn.dataset.act === 'del-campaign') confirmAction('حذف هذه الحملة؟', () => deleteCampaign(id));
    });
  });
}

function populateCampaignSelects() {
  const opts = state.campaigns.map(c => '<option value="' + c.id + '">' + esc(c.name) + '</option>').join('');
  ['tweetCampaignSelect', 'reportCampaignSelect', 'invCampaign'].forEach(id => {
    const el = $(id);
    if (el) el.innerHTML = opts || '<option value="">لا توجد حملات</option>';
  });
  if (state.currentCampaignId) $('tweetCampaignSelect').value = state.currentCampaignId;
}

function openCampaignModal(id = null) {
  state.editingCampaignId = id;
  $('campaignModalTitle').textContent = id ? 'تعديل الحملة' : 'حملة جديدة';
  $('cmpError').classList.add('hidden');
  const c = id ? state.campaigns.find(x => x.id === id) : null;
  $('cmpName').value = c ? c.name : '';
  $('cmpVideo').value = c ? (c.video_url || '') : '';
  $('cmpHashtag').value = c ? (c.hashtag || '') : '';
  $('cmpDescription').value = c ? (c.description || '') : '';
  $('cmpActive').checked = c ? c.is_active !== false : true;
  const splitDT = (iso) => {
    if (!iso) return ['', ''];
    const d = new Date(iso);
    if (isNaN(d)) return ['', ''];
    return [d.toISOString().split('T')[0], d.toTimeString().substring(0, 5)];
  };
  const [td, tt] = splitDT(c ? c.target_time : null);
  $('cmpTargetDate').value = td; $('cmpTargetTime').value = tt;
  openModal('campaignModal');
}

async function saveCampaign() {
  const errEl = $('cmpError');
  errEl.classList.add('hidden');
  const name = $('cmpName').value.trim();
  const date = $('cmpTargetDate').value;
  const time = $('cmpTargetTime').value;
  if (!name) { errEl.textContent = 'اسم الحملة مطلوب'; errEl.classList.remove('hidden'); return; }
  if (!date || !time) { errEl.textContent = 'تاريخ ووقت الإطلاق مطلوبان'; errEl.classList.remove('hidden'); return; }
  const payload = {
    type: 'campaign', campaignId: state.editingCampaignId || undefined,
    campaignName: name, videoUrl: $('cmpVideo').value.trim() || null,
    hashtag: $('cmpHashtag').value.trim(), description: $('cmpDescription').value.trim(),
    targetTime: new Date(date + 'T' + time).toISOString(),
    targetTimezone: 'Asia/Riyadh', timezoneLabel: 'توقيت مكة المكرمة (GMT+3)',
    isActive: $('cmpActive').checked
  };
  try {
    await api.post('/api/update', payload);
    closeModal('campaignModal');
    showToast('تم الحفظ', 'success');
    await loadCampaigns();
  } catch (err) { errEl.textContent = err.message; errEl.classList.remove('hidden'); }
}

async function deleteCampaign(id) {
  try { await api.post('/api/delete-campaign', { id }); showToast('تم الحذف', 'success'); await loadCampaigns(); }
  catch (err) { showToast(err.message, 'error'); }
}

async function loadTweetsSection() {
  populateCampaignSelects();
  if (!state.currentCampaignId && state.campaigns.length) {
    state.currentCampaignId = state.campaigns[0].id;
    $('tweetCampaignSelect').value = state.currentCampaignId;
  }
  await loadTweets();
}

async function loadTweets() {
  const tbody = $('tweetsTbody');
  if (!state.currentCampaignId) { $('tweetsTableWrap').classList.add('hidden'); $('tweetsEmpty').classList.remove('hidden'); return; }
  try {
    const data = await api.get('/api/campaign?id=' + state.currentCampaignId);
    state.tweets = data.tweets || [];
    renderTweets();
  } catch (err) { showToast(err.message, 'error'); }
}

function renderTweets() {
  const tbody = $('tweetsTbody');
  tbody.innerHTML = '';
  $('tweetsEmpty').classList.toggle('hidden', state.tweets.length > 0);
  $('tweetsTableWrap').classList.toggle('hidden', state.tweets.length === 0);
  state.tweets.forEach((t, i) => {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td>' + (i + 1) + '</td><td class="text-sm">' + esc(t.title || '—') + '</td><td style="max-width:340px"><p class="text-sm whitespace-pre-wrap">' + esc(t.text) + '</p></td><td>' + (t.media_url ? '🖼️' : '—') + '</td><td>' + (t.created_by_type === 'sub' ? '<span class="badge badge-info">فرعي</span>' : '<span class="badge badge-muted">رئيسي</span>') + '</td><td><div class="flex gap-1">' + (hasPerm('canEditTweets') ? '<button class="btn btn-ghost btn-sm" data-tact="edit" data-id="' + t.id + '">تعديل</button>' : '') + (hasPerm('canDeleteTweets') ? '<button class="btn btn-danger btn-sm" data-tact="del" data-id="' + t.id + '">حذف</button>' : '') + '</div></td>';
    tbody.appendChild(tr);
  });
  tbody.querySelectorAll('[data-tact]').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = parseInt(btn.dataset.id, 10);
      if (btn.dataset.tact === 'edit') openTweetModal(id);
      if (btn.dataset.tact === 'del') confirmAction('حذف التغريدة؟', () => deleteTweet(id));
    });
  });
}

function openTweetModal(id = null) {
  state.editingTweetId = id;
  $('tweetModalTitle').textContent = id ? 'تعديل التغريدة' : 'تغريدة جديدة';
  $('twError').classList.add('hidden');
  const t = id ? state.tweets.find(x => x.id === id) : null;
  $('twTitle').value = t ? (t.title || '') : '';
  $('twText').value = t ? t.text : '';
  $('twMedia').value = t ? (t.media_url || '') : '';
  updateTweetCounter();
  openModal('tweetModal');
}

function updateTweetCounter() { $('twCounter').textContent = $('twText').value.length; }

async function saveTweet() {
  const errEl = $('twError');
  errEl.classList.add('hidden');
  const text = $('twText').value.trim();
  if (!text) { errEl.textContent = 'نص التغريدة مطلوب'; errEl.classList.remove('hidden'); return; }
  if (text.length > 280) { errEl.textContent = 'النص يتجاوز 280 حرفاً'; errEl.classList.remove('hidden'); return; }
  try {
    await api.post('/api/update', { type: 'tweet', tweetId: state.editingTweetId || undefined, campaignId: state.currentCampaignId, tweetTitle: $('twTitle').value.trim(), tweetText: text, mediaUrl: $('twMedia').value.trim() || null });
    closeModal('tweetModal');
    showToast('تم الحفظ', 'success');
    await loadTweets();
  } catch (err) { errEl.textContent = err.message; errEl.classList.remove('hidden'); }
}

async function deleteTweet(id) {
  try { await api.post('/api/delete-tweet', { id }); showToast('تم الحذف', 'success'); await loadTweets(); }
  catch (err) { showToast(err.message, 'error'); }
}

function parseCSV(text) {
  const rows = [];
  let row = [], field = '', inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) { if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else inQ = false; } else field += c; }
    else { if (c === '"') inQ = true; else if (c === ',') { row.push(field); field = ''; } else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; } else if (c !== '\r') field += c; }
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  return rows.filter(r => r.some(cell => String(cell).trim() !== ''));
}

function rowsToTweets(rows) {
  if (!rows.length) return [];
  let start = 0;
  const first = rows[0].map(c => String(c).toLowerCase().trim());
  if (first.some(h => ['text', 'tweet', 'النص', 'نص'].includes(h))) start = 1;
  const out = [];
  for (let i = start; i < rows.length; i++) {
    const r = rows[i];
    let title = '', text = '', media = '';
    if (r.length >= 2) { title = String(r[0] || '').trim(); text = String(r[1] || '').trim(); media = String(r[2] || '').trim(); }
    else { text = String(r[0] || '').trim(); }
    if (text && text.length <= 280) out.push({ title: title.substring(0, 100), text, media_url: media });
  }
  return out;
}

async function handleExcelFile(file) {
  const errEl = $('excelError');
  errEl.classList.add('hidden');
  try {
    let rows = [];
    if (file.name.toLowerCase().endsWith('.csv')) { rows = parseCSV(await file.text()); }
    else if (window.XLSX) {
      const buf = await file.arrayBuffer();
      const wb = window.XLSX.read(buf, { type: 'array' });
      const ws = wb.Sheets[wb.SheetNames[0]];
      rows = window.XLSX.utils.sheet_to_json(ws, { header: 1 });
    } else { throw new Error('استخدم CSV أو أضف مكتبة xlsx محلياً'); }
    state.importRows = rowsToTweets(rows);
    if (!state.importRows.length) throw new Error('لم يتم العثور على تغريدات صالحة');
    const tbody = $('excelTbody');
    tbody.innerHTML = '';
    state.importRows.forEach((t, i) => {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td>' + (i + 1) + '</td><td class="text-sm">' + esc(t.title || '—') + '</td><td class="text-sm">' + esc(t.text) + '</td>';
      tbody.appendChild(tr);
    });
    $('excelCount').textContent = state.importRows.length;
    $('excelPreview').classList.remove('hidden');
    $('confirmImportBtn').disabled = false;
  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.remove('hidden');
    $('excelPreview').classList.add('hidden');
    $('confirmImportBtn').disabled = true;
  }
}

async function confirmImport() {
  if (!state.importRows.length || !state.currentCampaignId) return;
  try {
    const data = await api.post('/api/update', { type: 'excel_import', campaignId: state.currentCampaignId, tweets: state.importRows });
    closeModal('excelModal');
    showToast('تم استيراد ' + (data.count || state.importRows.length) + ' تغريدة', 'success');
    state.importRows = [];
    await loadTweets();
  } catch (err) { $('excelError').textContent = err.message; $('excelError').classList.remove('hidden'); }
}

async function loadSubAdmins() {
  const tbody = $('subAdminsTbody');
  tbody.innerHTML = '<tr><td colspan="7"><div class="skeleton" style="height:40px"></div></td></tr>';
  try {
    const data = await api.get('/api/sub-admins');
    state.subAdmins = data.subAdmins || [];
    renderSubAdmins();
  } catch (err) { showToast(err.message, 'error'); }
}

function renderSubAdmins() {
  const tbody = $('subAdminsTbody');
  tbody.innerHTML = '';
  $('subAdminsEmpty').classList.toggle('hidden', state.subAdmins.length > 0);
  state.subAdmins.forEach(sa => {
    const p = sa.permissions || {};
    const tr = document.createElement('tr');
    tr.innerHTML = '<td class="font-semibold">' + esc(sa.name) + '</td><td class="text-sm text-muted">' + esc(sa.username) + '</td><td>' + (sa.is_active ? '<span class="badge badge-success">نشط</span>' : '<span class="badge badge-danger">معطل</span>') + '</td><td><div class="flex gap-1 flex-wrap">' + (p.canAddTweets ? '<span class="badge badge-info">إضافة</span>' : '') + (p.canDeleteTweets ? '<span class="badge badge-warning">حذف</span>' : '') + (p.canImportExcel ? '<span class="badge badge-info">Excel</span>' : '') + '</div></td><td class="text-xs text-muted">' + (sa.last_login_at ? fmtDate(sa.last_login_at) : '—') + '</td><td><div class="flex gap-1"><button class="btn btn-ghost btn-sm" data-sact="edit" data-id="' + sa.id + '">تعديل</button><button class="btn ' + (sa.is_active ? 'btn-danger' : 'btn-secondary') + ' btn-sm" data-sact="toggle" data-id="' + sa.id + '">' + (sa.is_active ? 'تعطيل' : 'تفعيل') + '</button></div></td>';
    tbody.appendChild(tr);
  });
  tbody.querySelectorAll('[data-sact]').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = parseInt(btn.dataset.id, 10);
      if (btn.dataset.sact === 'edit') openSubAdminModal(id);
      if (btn.dataset.sact === 'toggle') toggleSubAdmin(id);
    });
  });
}

function openSubAdminModal(id = null) {
  state.editingSubAdminId = id;
  $('subAdminModalTitle').textContent = id ? 'تعديل المشرف' : 'مشرف جديد';
  $('saError').classList.add('hidden');
  const sa = id ? state.subAdmins.find(x => x.id === id) : null;
  $('saName').value = sa ? sa.name : '';
  $('saUsername').value = sa ? sa.username : '';
  $('saPassword').value = '';
  const p = sa ? sa.permissions : {};
  $('permAdd').checked = p.canAddTweets !== false;
  $('permEdit').checked = p.canEditTweets !== false;
  $('permDelete').checked = !!p.canDeleteTweets;
  $('permExcel').checked = p.canImportExcel !== false;
  $('permReports').checked = !!p.canViewReports;
  openModal('subAdminModal');
}

async function saveSubAdmin() {
  const errEl = $('saError');
  errEl.classList.add('hidden');
  const name = $('saName').value.trim();
  const username = $('saUsername').value.trim();
  const password = $('saPassword').value;
  if (!name || !username) { errEl.textContent = 'الاسم واسم المستخدم مطلوبان'; errEl.classList.remove('hidden'); return; }
  if (!state.editingSubAdminId && password.length < 6) { errEl.textContent = 'كلمة المرور 6 أحرف على الأقل'; errEl.classList.remove('hidden'); return; }
  const permissions = { canAddTweets: $('permAdd').checked, canEditTweets: $('permEdit').checked, canDeleteTweets: $('permDelete').checked, canImportExcel: $('permExcel').checked, canViewReports: $('permReports').checked };
  try {
    if (state.editingSubAdminId) {
      const payload = { id: state.editingSubAdminId, name, permissions };
      if (password) payload.password = password;
      await api.put('/api/sub-admins', payload);
    } else {
      await api.post('/api/sub-admins', { name, username, password, permissions });
    }
    closeModal('subAdminModal');
    showToast('تم الحفظ', 'success');
    await loadSubAdmins();
  } catch (err) { errEl.textContent = err.message; errEl.classList.remove('hidden'); }
}

async function toggleSubAdmin(id) {
  const sa = state.subAdmins.find(x => x.id === id);
  if (!sa) return;
  try {
    if (sa.is_active) { await api.del('/api/sub-admins', { id }); showToast('تم التعطيل', 'success'); }
    else { await api.put('/api/sub-admins', { id, isActive: true }); showToast('تم التفعيل', 'success'); }
    await loadSubAdmins();
  } catch (err) { showToast(err.message, 'error'); }
}

async function loadInvites() {
  populateCampaignSelects();
  const tbody = $('invitesTbody');
  tbody.innerHTML = '<tr><td colspan="5"><div class="skeleton" style="height:40px"></div></td></tr>';
  try {
    const data = await api.get('/api/invite-links');
    state.invites = data.inviteLinks || [];
    renderInvites();
  } catch (err) { showToast(err.message, 'error'); }
}

function renderInvites() {
  const tbody = $('invitesTbody');
  tbody.innerHTML = '';
  $('invitesEmpty').classList.toggle('hidden', state.invites.length > 0);
  state.invites.forEach(inv => {
    const url = location.origin + '/?ref=' + inv.code;
    const tr = document.createElement('tr');
    tr.innerHTML = '<td class="font-semibold">' + esc(inv.name) + '</td><td class="text-sm text-muted">' + esc(inv.code) + '</td><td><span class="kbd text-xs" dir="ltr">' + esc(url) + '</span></td><td>' + (inv.is_active ? '<span class="badge badge-success">نشط</span>' : '<span class="badge badge-muted">معطل</span>') + '</td><td><div class="flex gap-1"><button class="btn btn-primary btn-sm" data-iact="copy" data-url="' + esc(url) + '">نسخ</button><button class="btn ' + (inv.is_active ? 'btn-ghost' : 'btn-secondary') + ' btn-sm" data-iact="toggle" data-id="' + inv.id + '">' + (inv.is_active ? 'تعطيل' : 'تفعيل') + '</button></div></td>';
    tbody.appendChild(tr);
  });
  tbody.querySelectorAll('[data-iact]').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (btn.dataset.iact === 'copy') await copyText(btn.dataset.url);
      if (btn.dataset.iact === 'toggle') {
        const inv = state.invites.find(x => x.id === parseInt(btn.dataset.id, 10));
        if (!inv) return;
        try { await api.put('/api/invite-links', { id: inv.id, isActive: !inv.is_active }); showToast('تم التحديث', 'success'); await loadInvites(); }
        catch (err) { showToast(err.message, 'error'); }
      }
    });
  });
}

async function saveInvite() {
  const errEl = $('invError');
  errEl.classList.add('hidden');
  const campaignId = $('invCampaign').value;
  const name = $('invName').value.trim();
  if (!campaignId || !name) { errEl.textContent = 'الحملة والاسم مطلوبان'; errEl.classList.remove('hidden'); return; }
  try {
    await api.post('/api/invite-links', { campaignId: parseInt(campaignId, 10), name });
    closeModal('inviteModal');
    $('invName').value = '';
    showToast('تم إنشاء الرابط', 'success');
    await loadInvites();
  } catch (err) { errEl.textContent = err.message; errEl.classList.remove('hidden'); }
}

async function loadAnalytics() {
  $('statsCards').innerHTML = Array(6).fill('<div class="card skeleton" style="height:90px"></div>').join('');
  try {
    const data = await api.get('/api/analytics');
    renderAnalytics(data.summary || {});
  } catch (err) { showToast(err.message, 'error'); }
}

function renderAnalytics(s) {
  const cards = [
    { label: 'مشاهدات الصفحة', value: s.totalPageViews || 0 },
    { label: 'مشاهدات الحملات', value: s.totalCampaignViews || 0 },
    { label: 'إجمالي المشاركات', value: s.totalShareClicks || 0 },
    { label: 'عمليات النسخ', value: s.totalCopies || 0 },
    { label: 'زيارات الدعوة', value: s.totalInviteVisits || 0 },
    { label: 'زوار فريدون', value: s.uniqueVisitors || 0 }
  ];
  $('statsCards').innerHTML = cards.map(c => '<div class="card stat-card"><div class="stat-value">' + c.value + '</div><div class="stat-label">' + c.label + '</div></div>').join('');
}

function loadReportsSection() { populateCampaignSelects(); }

async function downloadReport() {
  const cid = $('reportCampaignSelect').value;
  if (!cid) { showToast('اختر حملة', 'error'); return; }
  try {
    const res = await api.request('/api/report?campaignId=' + cid + '&format=html', { raw: true });
    if (!res.ok) throw new Error('فشل توليد التقرير');
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'report-' + cid + '.html'; a.click();
    URL.revokeObjectURL(url);
    showToast('تم التحميل', 'success');
  } catch (err) { showToast(err.message, 'error'); }
}

function previewReport() {
  const cid = $('reportCampaignSelect').value;
  if (!cid) { showToast('اختر حملة', 'error'); return; }
  window.open('/api/report?campaignId=' + cid + '&format=pdf', '_blank', 'noopener,noreferrer');
}

function bindEvents() {
  $('loginForm').addEventListener('submit', handleLogin);
  $('logoutBtn').addEventListener('click', handleLogout);
  document.addEventListener('api:unauthorized', () => {
    $('appView').classList.add('hidden');
    $('loginView').classList.remove('hidden');
  });
  document.querySelectorAll('.nav-item[data-section]').forEach(btn => {
    btn.addEventListener('click', () => showSection(btn.dataset.section));
  });
  $('tweetCampaignSelect').addEventListener('change', (e) => {
    state.currentCampaignId = parseInt(e.target.value, 10) || null;
    loadTweets();
  });
  $('twText').addEventListener('input', updateTweetCounter);
  $('excelFile').addEventListener('change', (e) => {
    if (e.target.files[0]) handleExcelFile(e.target.files[0]);
  });
  document.addEventListener('click', (e) => {
    const actionEl = e.target.closest('[data-action]');
    const closeEl = e.target.closest('[data-close]');
    if (closeEl && closeEl.dataset.close) {
      if (closeEl.dataset.close === 'changePasswordModal' && state.pendingMustChange) return;
      closeModal(closeEl.dataset.close);
      return;
    }
    if (!actionEl) return;
    const actions = {
      'new-campaign': () => openCampaignModal(),
      'save-campaign': saveCampaign,
      'new-tweet': () => { if (!state.currentCampaignId) { showToast('اختر حملة', 'error'); return; } openTweetModal(); },
      'save-tweet': saveTweet,
      'excel-import': () => { if (!state.currentCampaignId) { showToast('اختر حملة', 'error'); return; } state.importRows = []; $('excelPreview').classList.add('hidden'); $('confirmImportBtn').disabled = true; openModal('excelModal'); },
      'confirm-import': confirmImport,
      'new-subadmin': () => openSubAdminModal(),
      'save-subadmin': saveSubAdmin,
      'new-invite': () => { populateCampaignSelects(); openModal('inviteModal'); },
      'save-invite': saveInvite,
      'refresh-stats': loadAnalytics,
      'download-report': downloadReport,
      'preview-report': previewReport,
      'save-password': handleChangePassword
    };
    if (actions[actionEl.dataset.action]) actions[actionEl.dataset.action]();
  });
}

document.addEventListener('DOMContentLoaded', init);
