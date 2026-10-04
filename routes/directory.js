// Lectures "annuaire" : comptes de demo (ecran de connexion), services, et liste des
// collaborateurs visibles par le compte connecte. Requetes toujours parametrees.

const express = require('express');
const db = require('../db');
const config = require('../config');
const { wrap, HttpError } = require('../lib/http');
const { isAdmin, requireAuth } = require('../lib/authz');
const { publicUser } = require('../middleware/session');

const router = express.Router();

const PUBLIC_FIELDS = 'id, full_name, username, email, department, role, manager_id, active';

// Comptes de demonstration, mots de passe compris, pour la soutenance : uniquement si
// DEMO_ACCOUNTS est actif (jamais en production). Aucune authentification requise.
// Seuls les 6 comptes du seed sont proposes, avec le mot de passe commun db.DEMO_PASSWORD
// (affiche meme si quelqu'un l'a change depuis : l'ecran de connexion echouera alors).
const SEED_USERNAMES = ['alice.martin', 'bassirou.koffi', 'nadia.benali', 'julien.picard', 'fatou.diarra', 'admin'];
router.get('/demo-accounts', wrap(async (req, res) => {
  if (!config.demoAccounts) throw new HttpError(404, 'Ressource introuvable.');
  const rows = await db.p.all('SELECT username, full_name, role, department FROM users WHERE active = 1 ORDER BY full_name');
  res.json(rows.filter((r) => SEED_USERNAMES.includes(r.username)).map((r) => ({ ...r, password: db.DEMO_PASSWORD })));
}));

router.get('/departments', requireAuth, wrap(async (req, res) => {
  res.json(await db.p.all('SELECT id, name, budget, location FROM departments ORDER BY name'));
}));

// Annuaire : limite a ce que le compte connecte a le droit de voir (lui-meme + ses
// subordonnes directs ; tout pour l'Administrateur). Les comptes desactives ne sont
// visibles que de l'Administrateur.
router.get('/employees', requireAuth, wrap(async (req, res) => {
  const me = req.user;
  const rows = isAdmin(me)
    ? await db.p.all(`SELECT ${PUBLIC_FIELDS} FROM users ORDER BY full_name`)
    : await db.p.all(
      `SELECT ${PUBLIC_FIELDS} FROM users WHERE active = 1 AND (id = ? OR manager_id = ?) ORDER BY full_name`,
      [me.id, me.id]);
  res.json({
    session: { id: me.id, full_name: me.full_name, role: me.role },
    user: publicUser(me),
    employees: rows,
  });
}));

module.exports = router;
