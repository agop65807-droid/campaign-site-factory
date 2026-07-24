/* Shared API helper — token-aware fetch wrapper */
function createApi(storageKey, base = '') {
  return {
    getToken() {
      const token = sessionStorage.getItem(storageKey);
      const legacyToken = localStorage.getItem(storageKey);
      if (!token && legacyToken) {
        sessionStorage.setItem(storageKey, legacyToken);
        localStorage.removeItem(storageKey);
        return legacyToken;
      }
      return token;
    },
    setToken(t) {
      localStorage.removeItem(storageKey);
      t ? sessionStorage.setItem(storageKey, t) : sessionStorage.removeItem(storageKey);
    },
    async request(path, { method = 'GET', body, auth = true, raw = false } = {}) {
      const headers = {};
      if (body && !(body instanceof FormData)) headers['Content-Type'] = 'application/json';
      if (auth && this.getToken()) headers['Authorization'] = 'Bearer ' + this.getToken();
      const res = await fetch(base + path, {
        method, headers,
        body: body instanceof FormData ? body : (body ? JSON.stringify(body) : undefined)
      });
      if (res.status === 401 && auth) {
        this.setToken(null);
        document.dispatchEvent(new CustomEvent('api:unauthorized'));
      }
      if (raw) return res;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const error = new Error(data.error || ('HTTP ' + res.status));
        error.status = res.status;
        error.data = data;
        throw error;
      }
      return data;
    },
    get(p, o)  { return this.request(p, { ...o, method: 'GET' }); },
    post(p, b, o) { return this.request(p, { ...o, method: 'POST', body: b }); },
    put(p, b, o)  { return this.request(p, { ...o, method: 'PUT', body: b }); },
    del(p, b, o)  { return this.request(p, { ...o, method: 'DELETE', body: b }); }
  };
}

/* Shared UI helpers */
function esc(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
function $(id) { return document.getElementById(id); }
function showToast(msg, type = 'info') {
  let c = $('toastContainer');
  if (!c) { c = document.createElement('div'); c.id = 'toastContainer'; document.body.appendChild(c); }
  const t = document.createElement('div');
  t.className = 'toast toast-' + type;
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => { t.style.transition = 'opacity .3s'; t.style.opacity = '0'; setTimeout(() => t.remove(), 300); }, 3400);
}
function openModal(id) { $(id).classList.remove('hidden'); }
function closeModal(id) { $(id).classList.add('hidden'); }
function fmtDate(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleString('ar-SA', { year:'numeric', month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' }); }
  catch { return iso; }
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); showToast('تم النسخ', 'success'); }
  catch { showToast('تعذّر النسخ', 'error'); }
}
