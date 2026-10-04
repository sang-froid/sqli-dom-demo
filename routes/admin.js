// Administration (reservee au role Administrateur) : gestion des comptes et des services,
// consultation du journal d'audit et de l'historique de connexion.
// Les noms de colonnes dynamiques viennent d'une liste blanche ; toutes les valeurs sont
// des parametres lies.

const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db');
const config = require('../config');
const v = require('../lib/validate');
const { HttpError, wrap } = require('../lib/http');
const { requireAdmin } = require('../lib/authz');
const { audit } = require('../lib/audit');
const { destroyUserSessions } = require('../middleware/session');

const router = express.Router();
router.use(requireAdmin);

const ADMIN_ROLE = 'Administrateur';
const USER_LIST_SQL = `
  SELECT u.id, u.full_name, u.username, u.email, u.department, u.role, u.manager_id,
         m.full_name AS manager_name, u.phone, u.hire_date, u.site, u.bio, u.active
  FROM users u LEFT JOIN users m ON m.id = u.manager_id`;

// ------------------------------------------------------------------ comptes
router.get('/users', wrap(async (req, res) => {
  res.json(await db.p.all(`${USER_LIST_SQL} ORDER BY u.full_name`));
}));

async function assertDepartment(name) {
  if (!(await db.p.get('SELECT 1 AS ok FROM departments WHERE name = ?', [name]))) {
    throw new HttpError(400, 'Service inconnu.');
  }
}

// Le manager doit exister, etre actif, ne pas etre le compte lui-meme ni l'un de ses
// propres subordonnes (pas de cycle dans la hierarchie).
async function assertManager(managerId, userId) {
  if (managerId === null) return;
  if (managerId === userId) throw new HttpError(400, 'Un compte ne peut pas etre son propre manager.');
  const mgr = await db.p.get('SELECT id, active, manager_id FROM users WHERE id = ?', [managerId]);
  if (!mgr || !mgr.active) throw new HttpError(400, 'Manager inconnu ou desactive.');
  if (userId === null) return; // creation : le nouveau compte n'a pas encore de subordonnes
  let cursor = mgr;
  for (let depth = 0; cursor && depth < 50; depth++) {
    if (cursor.manager_id === userId) throw new HttpError(400, 'Ce manager est deja un subordonne de ce compte.');
    cursor = cursor.manager_id ? await db.p.get('SELECT id, manager_id FROM users WHERE id = ?', [cursor.manager_id]) : null;
  }
}

async function assertAdminRemains(userId) {
  const { n } = await db.p.get(
    'SELECT COUNT(*) AS n FROM users WHERE role = ? AND active = 1 AND id != ?', [ADMIN_ROLE, userId]);
  if (n === 0) throw new HttpError(409, 'Impossible : il doit rester au moins un administrateur actif.');
}

router.post('/users', wrap(async (req, res) => {
  const b = req.body || {};
  const data = {
    full_name: v.string(b, 'full_name', 'Le nom', { min: 2, max: 80 }),
    username: v.username(b),
    email: v.email(b),
    department: v.string(b, 'department', 'Le service', { max: 80 }),
    role: v.string(b, 'role', 'Le role', { max: 60 }),
    manager_id: v.int(b, 'manager_id', 'Le manager', { min: 1, optional: true }),
    phone: v.string(b, 'phone', 'Le telephone', { max: 30, optional: true }),
    hire_date: v.date(b, 'hire_date', 'La date d\'arrivee'),
    site: v.string(b, 'site', 'Le site', { max: 60, optional: true }),
    bio: v.string(b, 'bio', 'La bio', { max: 500, optional: true }),
  };
  v.password(b.password);
  await assertDepartment(data.department);
  await assertManager(data.manager_id, null);
  if (await db.p.get('SELECT 1 AS ok FROM users WHERE username = ?', [data.username])) {
    throw new HttpError(409, 'Ce nom d\'utilisateur existe deja.');
  }
  if (await db.p.get('SELECT 1 AS ok FROM users WHERE email = ?', [data.email])) {
    throw new HttpError(409, 'Cet e-mail est deja utilise.');
  }

  const hash = await bcrypt.hash(b.password, config.bcryptRounds);
  const { lastID } = await db.p.run(
    `INSERT INTO users (full_name, username, email, department, role, password, manager_id, phone, hire_date, site, bio)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [data.full_name, data.username, data.email, data.department, data.role, hash, data.manager_id,
      data.phone, data.hire_date, data.site, data.bio]);
  await audit(req.user.id, 'user_create', 'user', lastID, { username: data.username, role: data.role });
  res.status(201).json(await db.p.get(`${USER_LIST_SQL} WHERE u.id = ?`, [lastID]));
}));

router.patch('/users/:id', wrap(async (req, res) => {
  const id = v.idParam(req);
  const target = await db.p.get('SELECT * FROM users WHERE id = ?', [id]);
  if (!target) throw new HttpError(404, 'Compte introuvable.');
  const b = req.body || {};

  // Liste blanche : champ -> validateur. Seuls les champs presents sont modifies.
  const validators = {
    full_name: () => v.string(b, 'full_name', 'Le nom', { min: 2, max: 80 }),
    username: () => v.username(b),
    email: () => v.email(b),
    department: () => v.string(b, 'department', 'Le service', { max: 80 }),
    role: () => v.string(b, 'role', 'Le role', { max: 60 }),
    manager_id: () => v.int(b, 'manager_id', 'Le manager', { min: 1, optional: true }),
    phone: () => v.string(b, 'phone', 'Le telephone', { max: 30, optional: true }),
    hire_date: () => v.date(b, 'hire_date', 'La date d\'arrivee'),
    site: () => v.string(b, 'site', 'Le site', { max: 60, optional: true }),
    bio: () => v.string(b, 'bio', 'La bio', { max: 500, optional: true }),
    active: () => (v.bool(b, 'active') ? 1 : 0),
  };
  const changes = {};
  for (const [field, check] of Object.entries(validators)) {
    if (b[field] !== undefined) changes[field] = check();
  }
  if (!Object.keys(changes).length) throw new HttpError(400, 'Aucune modification fournie.');

  if (changes.department !== undefined) await assertDepartment(changes.department);
  if (changes.manager_id !== undefined) await assertManager(changes.manager_id, id);
  if (changes.username !== undefined && changes.username.toLowerCase() !== target.username.toLowerCase()
      && await db.p.get('SELECT 1 AS ok FROM users WHERE username = ? AND id != ?', [changes.username, id])) {
    throw new HttpError(409, 'Ce nom d\'utilisateur existe deja.');
  }
  if (changes.email !== undefined
      && await db.p.get('SELECT 1 AS ok FROM users WHERE email = ? AND id != ?', [changes.email, id])) {
    throw new HttpError(409, 'Cet e-mail est deja utilise.');
  }

  const losesAdmin = target.role === ADMIN_ROLE && target.active
    && ((changes.role !== undefined && changes.role !== ADMIN_ROLE) || changes.active === 0);
  if (changes.active === 0 && id === req.user.id) throw new HttpError(409, 'Vous ne pouvez pas desactiver votre propre compte.');
  if (losesAdmin) await assertAdminRemains(id);

  const cols = Object.keys(changes); // noms issus de la liste blanche ci-dessus
  await db.p.run(`UPDATE users SET ${cols.map((c) => `${c} = ?`).join(', ')} WHERE id = ?`,
    [...cols.map((c) => changes[c]), id]);
  if (changes.active === 0) await destroyUserSessions(id);
  await audit(req.user.id, 'user_update', 'user', id, changes);
  res.json(await db.p.get(`${USER_LIST_SQL} WHERE u.id = ?`, [id]));
}));

router.post('/users/:id/password', wrap(async (req, res) => {
  const id = v.idParam(req);
  if (!(await db.p.get('SELECT 1 AS ok FROM users WHERE id = ?', [id]))) throw new HttpError(404, 'Compte introuvable.');
  v.password((req.body || {}).password);
  await db.p.run('UPDATE users SET password = ? WHERE id = ?', [await bcrypt.hash(req.body.password, config.bcryptRounds), id]);
  await destroyUserSessions(id); // l'ancienne session ne doit pas survivre a la reinitialisation
  await audit(req.user.id, 'password_reset', 'user', id);
  res.json({ ok: true });
}));

// ------------------------------------------------------------------ services
function departmentInput(b) {
  return {
    name: v.string(b, 'name', 'Le nom du service', { max: 80 }),
    budget: v.int(b, 'budget', 'Le budget', { min: 0 }),
    location: v.string(b, 'location', 'Le lieu', { max: 80 }),
  };
}

router.post('/departments', wrap(async (req, res) => {
  const d = departmentInput(req.body || {});
  if (await db.p.get('SELECT 1 AS ok FROM departments WHERE name = ?', [d.name])) {
    throw new HttpError(409, 'Ce service existe deja.');
  }
  const { lastID } = await db.p.run('INSERT INTO departments (name, budget, location) VALUES (?, ?, ?)', [d.name, d.budget, d.location]);
  await audit(req.user.id, 'department_create', 'department', lastID, d);
  res.status(201).json(await db.p.get('SELECT * FROM departments WHERE id = ?', [lastID]));
}));

router.patch('/departments/:id', wrap(async (req, res) => {
  const id = v.idParam(req);
  const current = await db.p.get('SELECT * FROM departments WHERE id = ?', [id]);
  if (!current) throw new HttpError(404, 'Service introuvable.');
  const d = departmentInput(req.body || {});
  if (await db.p.get('SELECT 1 AS ok FROM departments WHERE name = ? AND id != ?', [d.name, id])) {
    throw new HttpError(409, 'Ce service existe deja.');
  }
  await db.p.tx(async (t) => {
    await t.run('UPDATE departments SET name = ?, budget = ?, location = ? WHERE id = ?', [d.name, d.budget, d.location, id]);
    // users.department stocke le nom du service : on le repercute.
    if (d.name !== current.name) await t.run('UPDATE users SET department = ? WHERE department = ?', [d.name, current.name]);
  });
  await audit(req.user.id, 'department_update', 'department', id, d);
  res.json(await db.p.get('SELECT * FROM departments WHERE id = ?', [id]));
}));

router.delete('/departments/:id', wrap(async (req, res) => {
  const id = v.idParam(req);
  const current = await db.p.get('SELECT * FROM departments WHERE id = ?', [id]);
  if (!current) throw new HttpError(404, 'Service introuvable.');
  const users = await db.p.get('SELECT COUNT(*) AS n FROM users WHERE department = ?', [current.name]);
  const projects = await db.p.get('SELECT COUNT(*) AS n FROM projects WHERE department_id = ?', [id]);
  if (users.n || projects.n) {
    throw new HttpError(409, `Suppression impossible : ${users.n} compte(s) et ${projects.n} projet(s) y sont rattaches.`);
  }
  await db.p.run('DELETE FROM departments WHERE id = ?', [id]);
  await audit(req.user.id, 'department_delete', 'department', id, current.name);
  res.json({ ok: true });
}));

// ------------------------------------------------------------------ journaux
const limitParam = (req) => Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 500);

router.get('/audit', wrap(async (req, res) => {
  res.json(await db.p.all(
    `SELECT a.id, a.ts, a.action, a.target_type, a.target_id, a.detail, a.actor_id, u.full_name AS actor_name
     FROM audit_log a LEFT JOIN users u ON u.id = a.actor_id
     ORDER BY a.id DESC LIMIT ?`, [limitParam(req)]));
}));

router.get('/logins', wrap(async (req, res) => {
  res.json(await db.p.all(
    `SELECT l.id, l.ts, l.ip, l.success, l.user_id, u.full_name
     FROM login_history l JOIN users u ON u.id = l.user_id
     ORDER BY l.ts DESC, l.id DESC LIMIT ?`, [limitParam(req)]));
}));

module.exports = router;
