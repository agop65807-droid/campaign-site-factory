const api = createApi('campaign_token');

const state = {
  config: {},
  campaigns: [],
  currentCampaign: null,
  tweets: [],
  sharedSet: new Set(JSON.parse(localStorage.getItem('shared_tweets') || '[]')),
  countdownTimer: null
};

function getVisitorId() {
  let id = localStorage.getItem('visitor_id');
  if (!id) { id = crypto.randomUUID(); localStorage.setItem('visitor_id', id); }
  return id;
}

function getInviteCode() {
  return new URLSearchParams(location.search).get('ref') || null;
}

async function track(eventType, extra = {}) {
  try {
    await api.post('/api/analytics', {
      eventType,
      campaignId: state.currentCampaign?.id || null,
      inviteCode: getInviteCode(),
      visitorId: getVisitorId(),
      ...extra
    }, { auth: false });
  } catch (e) {}
}

function scrollToTweets() {
  document.getElementById('tweetsSection')?.scrollIntoView({ behavior: 'smooth' });
}

function applyIdentity(cfg) {
  state.config = cfg || {};
  const c = state.config;
  if (c.orgName) {
    document.getElementById('orgName').textContent = c.orgName;
    document.getElementById('footerName').textContent = c.orgName;
  }
  if (c.orgDescription || c.metaDescription) {
    document.getElementById('orgDescription').textContent = c.orgDescription || c.metaDescription;
  }
  if (c.logoUrl) document.getElementById('orgLogo').src = c.logoUrl;
  if (c.hashtag) {
    const b = document.getElementById('hashtagBadge');
    b.textContent = c.hashtag.startsWith('#') ? c.hashtag : '#' + c.hashtag;
    b.classList.remove('hidden');
  }
}

async function loadAll() {
  try {
    const [cfgRes, campRes] = await Promise.all([
      fetch('/api/config').then(r => r.json()),
      api.get('/api/campaign', { auth: false })
    ]);
    applyIdentity(cfgRes);
    state.campaigns = campRes.campaigns || (campRes.campaign ? [campRes.campaign] : []);
    if (!state.campaigns.length) {
      document.getElementById('emptyState').classList.remove('hidden');
      return;
    }
    if (state.campaigns.length > 1) {
      renderCampaignsList();
    } else {
      openCampaign(state.campaigns[0].id, campRes);
    }
  } catch (e) {
    console.error(e);
    document.getElementById('emptyState').classList.remove('hidden');
  } finally {
    document.getElementById('loader').classList.add('hidden');
  }
}

function renderCampaignsList() {
  const wrap = document.getElementById('campaignsList');
  document.getElementById('campaignsSection').classList.remove('hidden');
  wrap.innerHTML = '';
  state.campaigns.forEach(c => {
    const card = document.createElement('div');
    card.className = 'card tweet-card';
    card.style.cursor = 'pointer';
    card.innerHTML = `
      <div class="flex items-center justify-between gap-3">
        <h3 class="font-bold text-lg">${esc(c.name)}</h3>
        <span class="badge badge-success">نشطة</span>
      </div>
      ${c.description ? `<p class="text-sm text-muted mt-2">${esc(c.description).substring(0, 120)}</p>` : ''}
      ${c.hashtag ? `<span class="badge badge-info mt-3">${esc(c.hashtag)}</span>` : ''}
      <button class="btn btn-primary w-full mt-4">اضغط للمشاركة</button>
    `;
    card.addEventListener('click', () => openCampaign(c.id));
    wrap.appendChild(card);
  });
}

async function openCampaign(id, preloaded = null) {
  try {
    const data = preloaded || await api.get('/api/campaign?id=' + id, { auth: false });
    if (!data.campaign) return;
    state.currentCampaign = data.campaign;
    state.tweets = data.tweets || [];
    document.getElementById('campaignsSection').classList.add('hidden');
    document.getElementById('campaignView').classList.remove('hidden');
    renderCampaignHeader();
    renderTweets();
    updateProgress();
    track('campaign_view');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  } catch (e) {
    showToast('تعذّر تحميل الحملة', 'error');
  }
}

function renderCampaignHeader() {
  const c = state.currentCampaign;
  document.getElementById('campaignName').textContent = c.name || '';
  document.getElementById('campaignDescription').textContent = c.description || '';
  if (c.video_url) {
    document.getElementById('videoWrap').classList.remove('hidden');
    document.getElementById('campaignVideo').src = c.video_url;
  }
  startCountdown(c.target_time, c.timezone_label);
}

function startCountdown(targetIso, tzLabel) {
  if (state.countdownTimer) clearInterval(state.countdownTimer);
  const target = targetIso ? new Date(targetIso) : null;
  if (!target || isNaN(target.getTime()) || target.getTime() <= Date.now()) {
    document.getElementById('countdownWrap').classList.add('hidden');
    document.getElementById('launchedWrap').classList.remove('hidden');
    checkLaunchNotification();
    return;
  }
  document.getElementById('countdownWrap').classList.remove('hidden');
  document.getElementById('launchedWrap').classList.add('hidden');
  try {
    document.getElementById('launchDate').textContent = 'موعد الإطلاق: ' + target.toLocaleString('ar-SA', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' }) + (tzLabel ? ' — ' + tzLabel : '');
  } catch (e) {}
  const tick = () => {
    const diff = target.getTime() - Date.now();
    if (diff <= 0) {
      clearInterval(state.countdownTimer);
      document.getElementById('countdownWrap').classList.add('hidden');
      document.getElementById('launchedWrap').classList.remove('hidden');
      fireLaunchNotification();
      return;
    }
    document.getElementById('cdDays').textContent = Math.floor(diff / 86400000);
    document.getElementById('cdHours').textContent = Math.floor((diff % 86400000) / 3600000);
    document.getElementById('cdMins').textContent = Math.floor((diff % 3600000) / 60000);
    document.getElementById('cdSecs').textContent = Math.floor((diff % 60000) / 1000);
  };
  tick();
  state.countdownTimer = setInterval(tick, 1000);
}

function enabledPlatforms() {
  return state.config.enabledSharePlatforms || ['x', 'whatsapp', 'facebook', 'telegram'];
}

function renderTweets() {
  const wrap = document.getElementById('tweetsList');
  const sort = document.getElementById('sortSelect') ? document.getElementById('sortSelect').value : 'newest';
  let list = [...state.tweets];
  if (sort === 'longest') list.sort((a, b) => b.text.length - a.text.length);
  if (sort === 'shortest') list.sort((a, b) => a.text.length - b.text.length);
  wrap.innerHTML = '';
  if (!list.length) {
    wrap.innerHTML = '<div class="card empty-state"><div class="icon">🐦</div><p>لا توجد تغريدات متاحة حالياً</p></div>';
    return;
  }
  list.forEach((tweet, i) => {
    const shared = state.sharedSet.has(String(tweet.id));
    const card = document.createElement('div');
    card.className = 'card tweet-card';
    card.style.animationDelay = (i * 0.05) + 's';
    card.innerHTML = `
      ${tweet.title ? `<p class="text-xs font-bold text-secondary mb-2">${esc(tweet.title)}</p>` : ''}
      <p class="tweet-text">${esc(tweet.text)}</p>
      ${tweet.media_url ? `<div class="mt-3"><span class="badge badge-info">تحتوي على وسائط</span></div>` : ''}
      <div class="flex items-center justify-between flex-wrap gap-3 mt-4" style="border-top:1px solid rgb(var(--c-border)/.4);padding-top:14px">
        <div class="flex gap-2 flex-wrap">
          ${shared ? '<span class="badge badge-success">✓ تمت المشاركة</span>' : `<button class="btn btn-primary btn-sm share-now" data-id="${tweet.id}">شارك الآن</button>`}
          <button class="btn btn-ghost btn-sm more-share" data-id="${tweet.id}">المزيد</button>
        </div>
        <span class="text-xs text-muted">${esc(String(tweet.text.length))}/280</span>
      </div>
    `;
    card.querySelector('.share-now')?.addEventListener('click', () => quickShare(tweet));
    card.querySelector('.more-share').addEventListener('click', () => openShareModal(tweet));
    wrap.appendChild(card);
  });
}

function buildShareLinks(text) {
  const enc = encodeURIComponent(text);
  const url = encodeURIComponent(location.href);
  return {
    x: `https://x.com/intent/tweet?text=${enc}`,
    whatsapp: `https://wa.me/?text=${enc}`,
    facebook: `https://www.facebook.com/sharer/sharer.php?u=${url}&quote=${enc}`,
    telegram: `https://t.me/share/url?url=${url}&text=${enc}`,
    native: null
  };
}

const PLATFORM_META = {
  x: { label: 'X (تويتر)', cls: 'pf-x', event: 'tweet_share_x' },
  whatsapp: { label: 'واتساب', cls: 'pf-whatsapp', event: 'tweet_share_whatsapp' },
  facebook: { label: 'فيسبوك', cls: 'pf-facebook', event: 'tweet_share_facebook' },
  telegram: { label: 'تيليجرام', cls: 'pf-telegram', event: 'tweet_share_telegram' },
  native: { label: 'مشاركة أصلية', cls: 'pf-native', event: 'tweet_share_native' }
};

function markShared(tweetId) {
  state.sharedSet.add(String(tweetId));
  localStorage.setItem('shared_tweets', JSON.stringify([...state.sharedSet]));
  updateProgress();
  renderTweets();
}

async function shareTo(platform, tweet) {
  const links = buildShareLinks(tweet.text);
  const meta = PLATFORM_META[platform];
  track(meta.event, { tweetId: tweet.id, platform });
  if (platform === 'native' && navigator.share) {
    try { await navigator.share({ text: tweet.text, url: location.href }); } catch (e) {}
  } else if (links[platform]) {
    window.open(links[platform], '_blank', 'noopener,noreferrer');
  }
  markShared(tweet.id);
  closeModal('shareModal');
}

function quickShare(tweet) {
  const platforms = enabledPlatforms();
  if (platforms.length === 1) {
    shareTo(platforms[0], tweet);
  } else {
    openShareModal(tweet);
  }
}

function openShareModal(tweet) {
  document.getElementById('sharePreview').textContent = tweet.text;
  document.getElementById('shareCounter').textContent = tweet.text.length + '/280 حرف';
  document.getElementById('copyNotice').classList.add('hidden');
  const wrap = document.getElementById('shareButtons');
  wrap.innerHTML = '';
  const platforms = [...enabledPlatforms()];
  if (navigator.share && !platforms.includes('native')) platforms.push('native');
  platforms.forEach(p => {
    const meta = PLATFORM_META[p];
    if (!meta) return;
    const btn = document.createElement('button');
    btn.className = 'platform-btn ' + meta.cls;
    btn.textContent = meta.label;
    btn.addEventListener('click', () => shareTo(p, tweet));
    wrap.appendChild(btn);
  });
  const copyBtn = document.createElement('button');
  copyBtn.className = 'platform-btn pf-copy';
  copyBtn.textContent = 'نسخ النص';
  copyBtn.addEventListener('click', async () => {
    await copyText(tweet.text);
    track('tweet_copy', { tweetId: tweet.id });
    document.getElementById('copyNotice').classList.remove('hidden');
  });
  wrap.appendChild(copyBtn);
  openModal('shareModal');
}

function updateProgress() {
  const total = state.tweets.length;
  const done = state.tweets.filter(t => state.sharedSet.has(String(t.id))).length;
  const pct = total ? Math.round((done / total) * 100) : 0;
  document.getElementById('progressLabel').textContent = `${done}/${total} (${pct}%)`;
  document.getElementById('progressFill').style.width = pct + '%';
  document.getElementById('progressDone').classList.toggle('hidden', !(total > 0 && done >= total));
}

async function enableNotifications() {
  if (!('Notification' in window)) { showToast('متصفحك لا يدعم الإشعارات', 'error'); return; }
  const perm = await Notification.requestPermission();
  if (perm === 'granted') {
    localStorage.setItem('notify_on_launch', '1');
    document.getElementById('notifyBtn').textContent = 'التنبيه مفعّل';
    document.getElementById('notifyBtn').disabled = true;
    showToast('تم تفعيل التنبيه', 'success');
  } else {
    showToast('تم رفض إذن الإشعارات', 'error');
  }
}

function checkLaunchNotification() {
  if (localStorage.getItem('notify_on_launch') === '1') {
    document.getElementById('notifyBtn').textContent = 'الحملة متاحة — انضم الآن';
    document.getElementById('notifyBtn').disabled = true;
  }
}

function fireLaunchNotification() {
  if (localStorage.getItem('notify_on_launch') === '1' && Notification.permission === 'granted') {
    new Notification(state.config.orgName || 'الحملة', { body: 'الحملة انطلقت — شارك الآن!', icon: state.config.logoUrl || '/logo-dark.png' });
    localStorage.removeItem('notify_on_launch');
  }
  checkLaunchNotification();
}

function openQrModal() {
  const url = location.href.split('?')[0];
  document.getElementById('qrImage').src = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(url);
  track('qr_modal_open');
  openModal('qrModal');
}

function downloadQr() {
  const a = document.createElement('a');
  a.href = document.getElementById('qrImage').src;
  a.download = 'campaign-qr.png';
  a.target = '_blank';
  a.rel = 'noopener';
  a.click();
  track('qr_download');
}

document.addEventListener('DOMContentLoaded', () => {
  loadAll();
  track('page_view');
  if (getInviteCode()) track('invite_visit');
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }

  const btnScroll = document.getElementById('btnScrollToTweets');
  if (btnScroll) btnScroll.addEventListener('click', scrollToTweets);

  const btnQr = document.getElementById('btnOpenQr');
  if (btnQr) btnQr.addEventListener('click', openQrModal);

  const notifyBtn = document.getElementById('notifyBtn');
  if (notifyBtn) notifyBtn.addEventListener('click', enableNotifications);

  const btnReload = document.getElementById('btnReload');
  if (btnReload) btnReload.addEventListener('click', () => location.reload());

  const btnDownloadQr = document.getElementById('btnDownloadQr');
  if (btnDownloadQr) btnDownloadQr.addEventListener('click', downloadQr);

  const sortSelect = document.getElementById('sortSelect');
  if (sortSelect) sortSelect.addEventListener('change', renderTweets);

  const shareModal = document.getElementById('shareModal');
  if (shareModal) shareModal.addEventListener('click', (e) => { if (e.target === shareModal) closeModal('shareModal'); });

  const closeShare = document.getElementById('closeShareModal');
  if (closeShare) closeShare.addEventListener('click', () => closeModal('shareModal'));

  const qrModal = document.getElementById('qrModal');
  if (qrModal) qrModal.addEventListener('click', (e) => { if (e.target === qrModal) closeModal('qrModal'); });

  const closeQr = document.getElementById('closeQrModal');
  if (closeQr) closeQr.addEventListener('click', () => closeModal('qrModal'));
});
