// LES DEUX SURFACES VULNERABLES DU LABO, deux comportements pour les memes routes --
// vulnerable ou corrige -- selectionnes par le client via le parametre "mode".
//
// MODELE D'AUTORISATION : chaque employe ne peut voir que sa propre fiche, plus celles
// de ses subordonnes directs (colonne users.manager_id). L'Administrateur voit tout.
// Un document de projet confidentiel n'est visible que par les membres du projet
// concerne (plus l'Administrateur) -- voir isDocVisible().
// Le compte "connecte" vient de la session (cookie) : req.user, pose par
// middleware/session.js. Sa recherche est toujours parametree : l'authentification n'est
// PAS une surface vulnerable de ce labo.
//
// DEUX SURFACES, DEUX TECHNIQUES :
// - /api/profile : le filtre d'autorisation est concatene dans le MEME texte SQL que
//   l'identifiant demande. Un commentaire SQL ("-- ") dans l'identifiant coupe la
//   requete avant ce filtre et l'annule entierement -- l'injection contourne donc le
//   controle d'acces lui-meme, pas seulement "WHERE id = ...".
// - /api/search : une recherche avancee multi-criteres (nom, service, statut de projet)
//   construite en concatenant chaque filtre. Une injection UNION SELECT permet d'ajouter
//   des lignes venant d'une AUTRE table (documents confidentiels) au resultat affiche --
//   la demonstration la plus parlante de l'exfiltration inter-tables.
// En mode CORRIGE, les deux routes utilisent des requetes parametrees et verifient
// l'autorisation cote application : aucune valeur dans l'URL ne peut les affecter.
//
// Ces deux routes sont les SEULES a construire du SQL par concatenation. Toutes les
// routes d'ecriture (projets, documents, comptes...) sont parametrees.

const express = require('express');
const db = require('../db');
const { isAdmin, requireAuth } = require('../lib/authz');

const router = express.Router();
router.use(requireAuth);

const FULL_FIELDS = `u.id, u.full_name, u.username, u.email, u.department, u.role, u.password,
                      u.phone, u.hire_date, u.site, u.bio, u.manager_id, m.full_name AS manager_name`;

// ------------------------------------------------------------------
// Enrichissement de la fiche : projets du collaborateur (JOIN projects + departments),
// et pour chaque projet ses documents, avec redaction de ceux qui sont confidentiels
// et hors du perimetre du compte connecte. Toujours en requetes parametrees : ce n'est
// pas une surface d'injection, seulement la "vraie" partie relationnelle de la fiche.
// ------------------------------------------------------------------
function isDocVisible(sessionUser, doc, sessionProjectIds) {
  return !doc.confidential || isAdmin(sessionUser) || sessionProjectIds.has(doc.project_id);
}

function getSessionProjectIds(sessionUserId, cb) {
  db.all('SELECT project_id FROM project_members WHERE user_id = ?', [sessionUserId], (err, rows) => {
    if (err) return cb(err);
    cb(null, new Set(rows.map((r) => r.project_id)));
  });
}

function getProjectsForProfile(profileUserId, sessionUser, sessionProjectIds, cb) {
  const sql = `
    SELECT p.id, p.name, p.client, p.status, pm.role_on_project, d.name AS department_name
    FROM project_members pm
    JOIN projects p ON p.id = pm.project_id
    JOIN departments d ON d.id = p.department_id
    WHERE pm.user_id = ?
    ORDER BY p.name
  `;
  db.all(sql, [profileUserId], (err, projects) => {
    if (err) return cb(err);
    if (!projects.length) return cb(null, []);

    let remaining = projects.length;
    let failed = false;
    projects.forEach((proj) => {
      db.all('SELECT id, project_id, title, confidential, content FROM documents WHERE project_id = ?', [proj.id], (err, docs) => {
        if (failed) return;
        if (err) { failed = true; return cb(err); }
        proj.documents = docs.map((doc) => {
          const visible = isDocVisible(sessionUser, doc, sessionProjectIds);
          return {
            id: doc.id,
            title: doc.title,
            confidential: !!doc.confidential,
            content: visible ? doc.content : null,
            hidden: !visible,
          };
        });
        remaining--;
        if (remaining === 0 && !failed) cb(null, projects);
      });
    });
  });
}

function attachProjectsAndRespond(res, mode, sql, sessionUser, row) {
  getSessionProjectIds(sessionUser.id, (err, sessionProjectIds) => {
    if (err) return res.status(500).json({ mode, error: 'Erreur interne.', resultats: [] });
    getProjectsForProfile(row.id, sessionUser, sessionProjectIds, (err, projects) => {
      if (err) return res.status(500).json({ mode, error: 'Erreur interne.', resultats: [] });
      res.json({ mode, sql_execute: sql, resultats: [row], projects });
    });
  });
}

// ------------------------------------------------------------------
// Fiche profil : UNE SEULE fonctionnalite, DEUX implementations.
// Le client choisit via ?mode=vulnerable|secure (bascule visible dans l'UI).
// ------------------------------------------------------------------
router.get('/profile', (req, res) => {
  const id = req.query.id ?? '';
  const mode = req.query.mode === 'secure' ? 'secure' : 'vulnerable';
  const sessionUser = req.user;

  if (mode === 'vulnerable') {
    // La valeur recue est collee directement dans le texte SQL, y compris a cote
    // du filtre d'autorisation -- c'est ce filtre qu'un commentaire SQL neutralise.
    let sql = `SELECT ${FULL_FIELDS} FROM users u LEFT JOIN users m ON u.manager_id = m.id WHERE u.id = ${id}`;
    if (!isAdmin(sessionUser)) {
      sql += ` AND (u.id = ${sessionUser.id} OR u.manager_id = ${sessionUser.id})`;
    }
    console.log('[VULNERABLE] SQL execute :', sql);
    req.sqlLog({ mode, sql, id, sessionUserId: sessionUser.id });

    return db.all(sql, [], (err, rows) => {
      if (err) {
        // Volontairement verbeux ICI pour l'exercice pedagogique (montrer le probleme).
        console.error('[VULNERABLE] Erreur SQL :', err.message);
        return res.status(500).json({ mode, sql_execute: sql, error: err.message, resultats: [] });
      }
      if (rows.length === 1) return attachProjectsAndRespond(res, mode, sql, sessionUser, rows[0]);
      res.json({ mode, sql_execute: sql, resultats: rows });
    });
  }

  // mode === 'secure' : requete parametree + validation du format, PUIS autorisation
  // verifiee en code -- aucune des deux etapes n'est influencable par l'URL.
  const rawId = String(id);
  const sql = `SELECT ${FULL_FIELDS} FROM users u LEFT JOIN users m ON u.manager_id = m.id WHERE u.id = ?`;

  if (!/^\d+$/.test(rawId)) {
    req.sqlLog({ mode, sql, id: rawId, sessionUserId: sessionUser.id, rejected: 'format' });
    return res.status(400).json({
      mode, sql_execute: sql,
      error: 'Parametre "id" invalide : un entier est attendu.',
      resultats: [],
    });
  }

  db.all(sql, [Number(rawId)], (err, rows) => {
    if (err) {
      console.error('[SECURE] Erreur SQL :', err.message);
      return res.status(500).json({ mode, error: 'Erreur interne.', resultats: [] });
    }
    const row = rows[0];
    if (!row) return res.json({ mode, sql_execute: sql, resultats: [] });

    const allowed = isAdmin(sessionUser) || row.id === sessionUser.id || row.manager_id === sessionUser.id;
    if (!allowed) {
      req.sqlLog({ mode, sql, id: rawId, sessionUserId: sessionUser.id, rejected: 'authorization' });
      return res.status(403).json({
        mode, sql_execute: sql,
        error: `Accès refusé : la fiche #${row.id} ne fait pas partie de votre périmètre.`,
        resultats: [],
      });
    }
    attachProjectsAndRespond(res, mode, sql, sessionUser, row);
  });
});

// ------------------------------------------------------------------
// Recherche avancee : nom + service + statut de projet, sur TROIS tables jointes
// (users, project_members, projects). C'est le pattern "formulaire de recherche"
// le plus courant en vrai -- et le terrain de la demonstration UNION-based.
// ------------------------------------------------------------------
const SEARCH_FIELDS = 'u.id, u.full_name, u.role, u.department, u.manager_id';

router.get('/search', (req, res) => {
  const mode = req.query.mode === 'secure' ? 'secure' : 'vulnerable';
  const q = req.query.q ?? '';
  const department = req.query.department ?? '';
  const status = req.query.status ?? '';
  const sessionUser = req.user;

  if (mode === 'vulnerable') {
    // Chaque filtre fourni est colle directement dans le texte SQL. Un seul '
    // echappe au litteral et ouvre la porte a un UNION SELECT venant d'une autre
    // table -- ici, les documents de projet, y compris les confidentiels.
    let sql = `SELECT ${SEARCH_FIELDS} FROM users u WHERE 1=1`;
    if (q) sql += ` AND u.full_name LIKE '%${q}%'`;
    if (department) sql += ` AND u.department = '${department}'`;
    if (status) {
      sql += ` AND u.id IN (SELECT pm.user_id FROM project_members pm JOIN projects p ON pm.project_id = p.id WHERE p.status = '${status}')`;
    }
    if (!isAdmin(sessionUser)) {
      sql += ` AND (u.id = ${sessionUser.id} OR u.manager_id = ${sessionUser.id})`;
    }
    sql += ` ORDER BY u.full_name`;

    console.log('[VULNERABLE] SQL recherche :', sql);
    req.sqlLog({ mode, sql, q, department, status, sessionUserId: sessionUser.id });

    return db.all(sql, [], (err, rows) => {
      if (err) {
        console.error('[VULNERABLE] Erreur SQL :', err.message);
        return res.status(500).json({ mode, sql_execute: sql, error: err.message, resultats: [] });
      }
      res.json({ mode, sql_execute: sql, resultats: rows });
    });
  }

  // mode === 'secure' : chaque filtre est parametre. Une apostrophe dans "q" reste
  // une donnee, jamais du SQL -- impossible d'ajouter un UNION SELECT de cette facon.
  // L'autorisation est reappliquee en code sur le resultat, pas dans la requete.
  let sql = `SELECT ${SEARCH_FIELDS} FROM users u WHERE 1=1`;
  const params = [];
  if (q) { sql += ` AND u.full_name LIKE ?`; params.push(`%${q}%`); }
  if (department) { sql += ` AND u.department = ?`; params.push(department); }
  if (status) {
    sql += ` AND u.id IN (SELECT pm.user_id FROM project_members pm JOIN projects p ON pm.project_id = p.id WHERE p.status = ?)`;
    params.push(status);
  }
  sql += ` ORDER BY u.full_name`;

  db.all(sql, params, (err, rows) => {
    if (err) {
      console.error('[SECURE] Erreur SQL :', err.message);
      return res.status(500).json({ mode, error: 'Erreur interne.', resultats: [] });
    }
    const scoped = isAdmin(sessionUser)
      ? rows
      : rows.filter((r) => r.id === sessionUser.id || r.manager_id === sessionUser.id);
    res.json({ mode, sql_execute: sql, resultats: scoped });
  });
});

module.exports = router;
