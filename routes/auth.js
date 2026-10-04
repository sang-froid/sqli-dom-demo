// Authentification : connexion / deconnexion, compte courant (/api/me), modification de
// son propre profil et de son mot de passe, historique de ses connexions.

const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db');
const config = require('../config');
const v = require('../lib/validate');
const { HttpError, wrap } = require('../lib/http');
const { requireAuth } = require('../lib/authz');
const { audit } = require('../lib/audit');
const {
  createSession, destroySession, destroyUserSessions, publicUser, createLoginLimiter,
} = require('../middleware/session');

const router = express.Router();
const limiter = createLoginLimiter();

// Hash factice : on compare toujours un mot de passe, meme pour un identifiant inconnu,
// pour que le temps de reponse ne revele pas quels comptes existent.
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', config.bcryptRounds);

async function recordLogin(userId, ip, success) {
  await db.p.run('INSERT INTO login_history (user_id, ts, ip, success) VALUES (?, ?, ?, ?)',
    [userId, new Date().toISOString(), ip || 'inconnue', success ? 1 : 0]);
}

router.post('/auth/login', wrap(async (req, res) => {
  const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (!username || !password) throw new HttpError(400, 'Identifiant et mot de passe requis.');

  const key = `${req.ip}|${username.toLowerCase()}`;
  const wait = limiter.retryAfterSeconds(key);
  if (wait) {
    res.setHeader('Retry-After', String(wait));
    throw new HttpError(429, `Trop de tentatives. Reessayez dans ${Math.ceil(wait / 60)} minute(s).`);
  }

  const user = await db.p.get('SELECT * FROM users WHERE username = ?', [username]);
  const passwordOk = await bcrypt.compare(password, user ? user.password : DUMMY_HASH);

  if (!user || !passwordOk || !user.active) {
    limiter.fail(key);
    if (user) {
      await recordLogin(user.id, req.ip, false);
      await audit(user.id, 'login_failed', 'user', user.id, user.active ? null : 'compte desactive');
    } else {
      await audit(null, 'login_failed', null, null, { username: username.slice(0, 64) });
    }
    throw new HttpError(401, 'Identifiant ou mot de passe incorrect.');
  }

  limiter.reset(key);
  await createSession(req, res, user.id); // nouveau jeton a chaque connexion
  await recordLogin(user.id, req.ip, true);
  const { n } = await db.p.get('SELECT COUNT(*) AS n FROM users WHERE manager_id = ? AND active = 1', [user.id]);
  user.is_manager = n > 0;
  res.json({ user: publicUser(user) });
}));

router.post('/auth/logout', wrap(async (req, res) => {
  await destroySession(req, res);
  res.json({ ok: true });
}));

router.get('/me', requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// Champs que chacun peut modifier sur sa propre fiche. Role, service, manager et
// identifiant restent reserves aux administrateurs.
router.patch('/me', requireAuth, wrap(async (req, res) => {
  const body = req.body || {};
  const next = {
    email: v.email(body),
    phone: v.string(body, 'phone', 'Le telephone', { max: 30, optional: true }),
    site: v.string(body, 'site', 'Le site', { max: 60, optional: true }),
    bio: v.string(body, 'bio', 'La bio', { max: 500, optional: true }),
  };
  const taken = await db.p.get('SELECT id FROM users WHERE email = ? AND id != ?', [next.email, req.user.id]);
  if (taken) throw new HttpError(409, 'Cet e-mail est deja utilise.');

  await db.p.run('UPDATE users SET email = ?, phone = ?, site = ?, bio = ? WHERE id = ?',
    [next.email, next.phone, next.site, next.bio, req.user.id]);
  await audit(req.user.id, 'profile_update', 'user', req.user.id, Object.keys(next));
  const fresh = await db.p.get('SELECT * FROM users WHERE id = ?', [req.user.id]);
  fresh.is_manager = req.user.is_manager;
  res.json({ user: publicUser(fresh) });
}));

router.post('/me/password', requireAuth, wrap(async (req, res) => {
  const { current, next } = req.body || {};
  if (typeof current !== 'string' || !(await bcrypt.compare(current, req.user.password))) {
    throw new HttpError(403, 'Mot de passe actuel incorrect.');
  }
  v.password(next, 'Le nouveau mot de passe');
  if (next === current) throw new HttpError(400, 'Le nouveau mot de passe doit etre different de l\'ancien.');

  await db.p.run('UPDATE users SET password = ? WHERE id = ?', [await bcrypt.hash(next, config.bcryptRounds), req.user.id]);
  await destroyUserSessions(req.user.id, req.sessionId); // deconnecte les autres appareils
  await audit(req.user.id, 'password_change', 'user', req.user.id);
  res.json({ ok: true });
}));

router.get('/me/logins', requireAuth, wrap(async (req, res) => {
  const rows = await db.p.all(
    'SELECT ts, ip, success FROM login_history WHERE user_id = ? ORDER BY ts DESC, id DESC LIMIT 20', [req.user.id]);
  res.json({ logins: rows });
}));

module.exports = router;
