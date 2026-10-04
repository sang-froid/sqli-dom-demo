// Logique partagee des pages : appels API (cookie de session + en-tete anti-CSRF),
// echappement HTML, barre laterale, notifications, mode demo (vulnerable/corrige) et
// panneau developpeur.
//
// La session est un cookie HttpOnly pose par le serveur : le JavaScript ne la voit jamais.
// localStorage ne sert qu'a retenir le mode demo (confort d'UI, jamais une preuve
// d'identite). Toute valeur issue de la base est echappee avant d'etre injectee en HTML :
// avec des ecritures, un nom ou une bio peut contenir du balisage.

const AtriumShell = (() => {
  const MODE_KEY = 'atrium_mode';

  // ---------------------------------------------------------------- helpers
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const initials = (name) => String(name || '?').split(' ').map((p) => p[0]).join('').slice(0, 2).toUpperCase();

  const fmtDate = (iso) => {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return esc(iso);
    return d.toLocaleDateString('fr-FR');
  };
  const fmtDateTime = (iso) => {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? esc(iso) : d.toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' });
  };
  const fmtMoney = (n) => `${Number(n).toLocaleString('fr-FR')} FCFA`;

  // ---------------------------------------------------------------- API
  class ApiError extends Error {
    constructor(status, message, data) { super(message); this.status = status; this.data = data; }
  }

  const pending = () => new Promise(() => {}); // la page est en train de rediriger

  // Renvoie { status, ok, data } sans lever d'erreur HTTP (sauf 401 : retour a la connexion).
  async function raw(path, { method = 'GET', body } = {}) {
    const opts = { method, headers: { 'X-Requested-With': 'atrium' } };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    let data = null;
    try { data = await res.json(); } catch { /* corps vide */ }
    if (res.status === 401 && !location.pathname.endsWith('login.html')) {
      location.href = 'login.html';
      return pending();
    }
    return { status: res.status, ok: res.ok, data };
  }

  async function api(path, options) {
    const r = await raw(path, options);
    if (!r.ok) throw new ApiError(r.status, (r.data && r.data.error) || 'Erreur inattendue.', r.data);
    return r.data;
  }

  // ---------------------------------------------------------------- notifications
  function toast(message, kind = '') {
    let stack = document.querySelector('.toast-stack');
    if (!stack) {
      stack = document.createElement('div');
      stack.className = 'toast-stack';
      stack.setAttribute('role', 'status');
      document.body.appendChild(stack);
    }
    const el = document.createElement('div');
    el.className = `toast ${kind}`;
    el.textContent = message;
    stack.appendChild(el);
    setTimeout(() => el.remove(), 4000);
  }

  // Affiche une erreur dans un bloc .form-error (ou en toast si absent).
  function showError(box, err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (!box) return toast(msg, 'bad');
    box.textContent = msg;
    box.classList.add('show');
  }
  const clearError = (box) => { if (box) { box.textContent = ''; box.classList.remove('show'); } };

  // ---------------------------------------------------------------- session + chrome
  const NAV = [
    { key: 'directory', href: 'directory.html', label: 'Annuaire' },
    { key: 'search', href: 'search.html', label: 'Recherche avancée' },
    { key: 'projects', href: 'projects.html', label: 'Projets' },
    { key: 'account', href: 'account.html', label: 'Mon compte' },
    { key: 'admin', href: 'admin.html', label: 'Administration', adminOnly: true },
  ];

  function roleLabel(user) {
    if (user.is_admin) return 'Administrateur';
    return user.is_manager ? `${user.role} · manager` : user.role;
  }

  function renderSidebar(user, active) {
    const el = document.getElementById('sidebar');
    if (!el) return;
    el.innerHTML = `
      <div class="brand"><span class="dot"></span> Atrium</div>
      <nav class="nav" aria-label="Navigation principale">
        ${NAV.filter((n) => !n.adminOnly || user.is_admin).map((n) => `
          <a href="${n.href}" ${n.key === active ? 'class="active" aria-current="page"' : ''}><span class="glyph"></span>${n.label}</a>`).join('')}
      </nav>
      <div class="spacer"></div>
      <div class="user-chip">
        <div class="avatar">${esc(initials(user.full_name))}</div>
        <div><div style="font-weight:700">${esc(user.full_name)}</div><div style="opacity:.7;font-size:.74rem">${esc(roleLabel(user))}</div></div>
      </div>
      <button class="logout" id="logout" type="button">Se déconnecter</button>`;
    document.getElementById('logout').addEventListener('click', async () => {
      try { await api('/api/auth/logout', { method: 'POST' }); } finally { location.href = 'login.html'; }
    });
  }

  // Affiche une erreur bloquante pleine page (serveur injoignable ou pas le bon serveur)
  // a la place d'une page vide qui ne dirait rien.
  function fatal(message) {
    const box = document.createElement('div');
    box.setAttribute('role', 'alert');
    box.style.cssText = 'max-width:560px;margin:12vh auto;padding:24px 28px;background:#f6e4de;'
      + 'border:1px solid #b5452e;border-radius:10px;font-family:system-ui,sans-serif;line-height:1.55;color:#22241f';
    box.innerHTML = `<b style="color:#b5452e">Atrium est injoignable</b><p style="margin:8px 0 0">${esc(message)}</p>`;
    document.body.innerHTML = '';
    document.body.appendChild(box);
    return pending();
  }

  // Charge le compte courant et dessine la barre laterale. Sans session (401), redirige
  // vers la connexion. Toute autre reponse inattendue (404 d'un autre serveur, serveur
  // arrete, ancienne version encore lancee) est signalee clairement.
  async function boot(active) {
    let r;
    try {
      r = await raw('/api/me');
    } catch {
      return fatal('Le serveur ne répond pas. Lancez-le avec « npm start » puis ouvrez http://localhost:3000.');
    }
    if (!r.ok || !r.data || !r.data.user) {
      return fatal(`L'API d'Atrium n'a pas répondu comme attendu (HTTP ${r.status}). `
        + 'Vérifiez que vous ouvrez bien l\'adresse du serveur Node (npm start, http://localhost:3000) '
        + 'et non un autre serveur de fichiers, et redémarrez-le s\'il tournait avant la dernière mise à jour.');
    }
    renderSidebar(r.data.user, active);
    return r.data.user;
  }

  // ---------------------------------------------------------------- mode demo
  function getMode() {
    try { return localStorage.getItem(MODE_KEY) === 'secure' ? 'secure' : 'vulnerable'; }
    catch { return 'vulnerable'; }
  }

  function setMode(mode) {
    try { localStorage.setItem(MODE_KEY, mode); } catch { /* stockage indisponible */ }
  }

  function initModeSwitch(toggleEl, tagEl) {
    const apply = (mode) => {
      toggleEl.dataset.on = String(mode === 'secure');
      toggleEl.setAttribute('role', 'switch');
      toggleEl.setAttribute('aria-checked', String(mode === 'secure'));
      toggleEl.setAttribute('aria-label', 'Mode démo : corrigé');
      tagEl.textContent = mode === 'secure' ? 'Corrigé' : 'Vulnérable';
      tagEl.className = 'mode-tag ' + (mode === 'secure' ? 'sec' : 'vuln');
    };
    apply(getMode());
    toggleEl.addEventListener('click', () => {
      const next = getMode() === 'secure' ? 'vulnerable' : 'secure';
      setMode(next);
      apply(next);
      document.dispatchEvent(new CustomEvent('atrium:mode-change', { detail: { mode: next } }));
    });
  }

  function initDevPanel(buttonEl, panelEl) {
    buttonEl.addEventListener('click', () => {
      panelEl.classList.toggle('open');
    });
  }

  return {
    esc, initials, fmtDate, fmtDateTime, fmtMoney,
    api, raw, ApiError, toast, showError, clearError,
    boot, getMode, setMode, initModeSwitch, initDevPanel,
  };
})();
