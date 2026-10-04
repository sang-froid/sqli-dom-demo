// Sessions serveur. Le cookie "atrium_sid" porte un jeton aleatoire de 256 bits ; seule
// son empreinte SHA-256 est stockee en base (table sessions), donc une fuite de la base ne
// permet pas de rejouer une session. Cookie HttpOnly + SameSite=Lax (+ Secure si
// COOKIE_SECURE). Le compte courant est recharge a chaque requete : desactiver un compte
// ou changer son role prend effet immediatement.

const crypto = require('crypto');
const db = require('../db');
const config = require('../config');

const COOKIE = 'atrium_sid';

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    if (k) out[k] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function cookieHeader(token, maxAgeSeconds) {
  const attrs = [`${COOKIE}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAgeSeconds}`];
  if (config.cookieSecure) attrs.push('Secure');
  return attrs.join('; ');
}

async function createSession(req, res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = new Date();
  const ttlMs = config.sessionTtlHours * 3600 * 1000;
  await db.p.run(
    'INSERT INTO sessions (id, user_id, created_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)',
    [sha256(token), userId, now.toISOString(), new Date(now.getTime() + ttlMs).toISOString(),
      req.ip, String(req.get('User-Agent') || '').slice(0, 200)]
  );
  res.setHeader('Set-Cookie', cookieHeader(token, Math.floor(ttlMs / 1000)));
}

async function destroySession(req, res) {
  if (req.sessionId) await db.p.run('DELETE FROM sessions WHERE id = ?', [req.sessionId]);
  res.setHeader('Set-Cookie', cookieHeader('', 0));
}

const destroyUserSessions = (userId, exceptId = null) =>
  db.p.run('DELETE FROM sessions WHERE user_id = ? AND id IS NOT ?', [userId, exceptId]);

const purgeExpiredSessions = () =>
  db.p.run('DELETE FROM sessions WHERE expires_at <= ?', [new Date().toISOString()]);

// Middleware : renseigne req.user (ligne users complete + is_manager) et req.sessionId,
// ou les laisse a null. Ne refuse rien : c'est requireAuth (lib/authz.js) qui decide.
async function loadSession(req, res, next) {
  req.user = null;
  req.sessionId = null;
  try {
    const token = parseCookies(req.headers.cookie)[COOKIE];
    if (token) {
      const sid = sha256(token);
      const user = await db.p.get(
        `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.id = ? AND s.expires_at > ? AND u.active = 1`,
        [sid, new Date().toISOString()]
      );
      if (user) {
        const { n } = await db.p.get('SELECT COUNT(*) AS n FROM users WHERE manager_id = ? AND active = 1', [user.id]);
        user.is_manager = n > 0;
        req.user = user;
        req.sessionId = sid;
      }
    }
    next();
  } catch (err) {
    next(err);
  }
}

// Vue du compte exposee au client : jamais le hash du mot de passe.
function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    full_name: u.full_name,
    username: u.username,
    email: u.email,
    department: u.department,
    role: u.role,
    manager_id: u.manager_id,
    phone: u.phone,
    hire_date: u.hire_date,
    site: u.site,
    bio: u.bio,
    active: !!u.active,
    is_admin: u.role === 'Administrateur',
    is_manager: !!u.is_manager,
  };
}

// Limiteur d'essais de connexion, en memoire : MAX echecs par (ip, identifiant) sur la fenetre.
function createLoginLimiter({ max = config.loginMaxAttempts, windowMs = config.loginWindowMinutes * 60000 } = {}) {
  const hits = new Map();
  const live = (key) => {
    const e = hits.get(key);
    if (e && e.resetAt <= Date.now()) { hits.delete(key); return null; }
    return e || null;
  };
  return {
    retryAfterSeconds(key) {
      const e = live(key);
      return e && e.count >= max ? Math.ceil((e.resetAt - Date.now()) / 1000) : 0;
    },
    fail(key) {
      const e = live(key) || { count: 0, resetAt: Date.now() + windowMs };
      e.count++;
      hits.set(key, e);
    },
    reset(key) { hits.delete(key); },
  };
}

module.exports = {
  loadSession, createSession, destroySession, destroyUserSessions, purgeExpiredSessions,
  publicUser, createLoginLimiter, sha256,
};
