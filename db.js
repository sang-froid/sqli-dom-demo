// Base de donnees SQLite d'Atrium.
// Donnees entierement fictives, uniquement pour le labo local.
//
// PERSISTANCE : la base est un fichier (DB_PATH, par defaut data/atrium.db). Le schema est
// cree avec CREATE TABLE IF NOT EXISTS et les donnees de demonstration ne sont inserees
// que si la table users est vide (premier demarrage). `npm run db:reset` supprime le
// fichier pour repartir de zero. DB_PATH=:memory: donne une base jetable (tests).
//
// Modele : chaque collaborateur a un manager_id (hierarchie simple). L'autorisation
// "qui peut voir la fiche de qui" repose sur cette colonne -- voir routes/lab.js.
// Les mots de passe sont stockes HACHES (bcrypt) : meme exfiltres via l'injection,
// ils ne sont pas directement exploitables.
//
// Schema multi-tables (departements, projets, documents, historique de connexion) :
// sert a rendre les requetes representatives d'une vraie appli (plusieurs JOIN), et a
// donner un terrain concret a l'injection UNION-based sur /api/search (voir
// routes/lab.js et docs/techniques-complementaires.md).
// Tables ajoutees pour l'application complete : sessions (cookie de session) et
// audit_log (journal des actions d'ecriture).

const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const config = require('./config');

if (config.dbPath !== ':memory:') fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });
const db = new sqlite3.Database(config.dbPath);

// Mot de passe commun a tous les comptes de demonstration (volontairement simple : labo
// local). Les comptes crees ensuite par un administrateur suivent la politique normale.
const DEMO_PASSWORD = 'Password123';

// ---------------------------------------------------------------- helpers a promesses
// db.p.get/all/run : memes requetes parametrees que db.get/all/run, version async.
// db.p.tx(fn) : execute fn dans une transaction ; les transactions sont serialisees entre
// elles (une seule connexion SQLite) et annulees si fn leve une erreur.
const p = {
  get: (sql, params = []) => new Promise((res, rej) => db.get(sql, params, (e, row) => (e ? rej(e) : res(row)))),
  all: (sql, params = []) => new Promise((res, rej) => db.all(sql, params, (e, rows) => (e ? rej(e) : res(rows)))),
  run: (sql, params = []) => new Promise((res, rej) => {
    db.run(sql, params, function onRun(e) { return e ? rej(e) : res({ lastID: this.lastID, changes: this.changes }); });
  }),
  exec: (sql) => new Promise((res, rej) => db.exec(sql, (e) => (e ? rej(e) : res()))),
};
let txChain = Promise.resolve();
p.tx = (fn) => {
  const run = txChain.then(async () => {
    await p.run('BEGIN');
    try {
      const result = await fn(p);
      await p.run('COMMIT');
      return result;
    } catch (err) {
      await p.run('ROLLBACK').catch(() => {});
      throw err;
    }
  });
  txChain = run.catch(() => {});
  return run;
};

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    full_name TEXT NOT NULL,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    department TEXT NOT NULL,
    role TEXT NOT NULL,
    password TEXT NOT NULL,
    manager_id INTEGER REFERENCES users(id),
    phone TEXT,
    hire_date TEXT,
    site TEXT,
    bio TEXT,
    active INTEGER NOT NULL DEFAULT 1
  );
  CREATE TABLE IF NOT EXISTS departments (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    budget INTEGER NOT NULL,
    location TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    client TEXT NOT NULL,
    budget INTEGER NOT NULL,
    status TEXT NOT NULL,
    department_id INTEGER NOT NULL REFERENCES departments(id),
    owner_id INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );
  CREATE TABLE IF NOT EXISTS project_members (
    project_id INTEGER NOT NULL REFERENCES projects(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    role_on_project TEXT NOT NULL,
    PRIMARY KEY (project_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id),
    title TEXT NOT NULL,
    confidential INTEGER NOT NULL DEFAULT 0,
    content TEXT NOT NULL,
    author_id INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT
  );
  CREATE TABLE IF NOT EXISTS login_history (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    ts TEXT NOT NULL,
    ip TEXT NOT NULL,
    success INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,                -- SHA-256 du jeton du cookie (jamais le jeton lui-meme)
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT
  );
  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor_id INTEGER,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id INTEGER,
    detail TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_members_user ON project_members(user_id);
  CREATE INDEX IF NOT EXISTS idx_documents_project ON documents(project_id);
`;

async function seed() {
  const hash = (plain) => bcrypt.hashSync(plain, config.bcryptRounds);

  await p.tx(async (t) => {
    // La hierarchie manager_id reference des lignes inserees plus loin : contraintes
    // verifiees au COMMIT seulement.
    await t.run('PRAGMA defer_foreign_keys = ON');

    const users = [
      [1, 'Alice Martin', 'alice.martin', 'alice.martin@atrium.test', 'Ingenierie', 'Collaborateur',
        DEMO_PASSWORD, 4, '+229 91 23 45 67', '2023-03-14', 'Cotonou',
        'Developpeuse full-stack, pole plateforme interne.'],
      [2, 'Bassirou Koffi', 'bassirou.koffi', 'bassirou.koffi@atrium.test', 'Ressources Humaines', 'Charge RH',
        DEMO_PASSWORD, null, '+229 96 11 22 33', '2021-09-01', 'Cotonou',
        "Gestion des recrutements et de l'integration des nouveaux arrivants."],
      [3, 'Nadia Benali', 'nadia.benali', 'nadia.benali@atrium.test', 'Finance', 'Controleuse',
        DEMO_PASSWORD, null, '+229 97 44 55 66', '2022-01-10', 'Porto-Novo',
        'Controle de gestion et clotures mensuelles.'],
      [4, 'Julien Picard', 'julien.picard', 'julien.picard@atrium.test', 'Ingenierie', 'Lead technique',
        DEMO_PASSWORD, null, '+229 90 10 20 30', '2019-06-01', 'Cotonou',
        "Encadre l'equipe plateforme, referent architecture."],
      [5, 'Fatou Diarra', 'fatou.diarra', 'fatou.diarra@atrium.test', 'Commercial', 'Responsable comptes',
        DEMO_PASSWORD, null, '+229 95 77 88 99', '2020-11-20', 'Cotonou',
        'Gere le portefeuille grands comptes regionaux.'],
      [6, 'Admin Systeme', 'admin', 'admin@atrium.test', 'Informatique', 'Administrateur',
        DEMO_PASSWORD, null, '+229 90 00 00 00', '2018-01-01', 'Cotonou',
        'Administration des systemes internes.'],
    ];
    for (const u of users) {
      const [id, fullName, username, email, dept, role, plain, ...rest] = u;
      await t.run(
        `INSERT INTO users (id, full_name, username, email, department, role, password,
                            manager_id, phone, hire_date, site, bio)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [id, fullName, username, email, dept, role, hash(plain), ...rest]
      );
    }

    const depts = [
      [1, 'Ingenierie', 450000, 'Cotonou'], [2, 'Ressources Humaines', 120000, 'Cotonou'],
      [3, 'Finance', 200000, 'Porto-Novo'], [4, 'Commercial', 300000, 'Cotonou'],
      [5, 'Informatique', 180000, 'Cotonou'],
    ];
    for (const d of depts) await t.run('INSERT INTO departments (id, name, budget, location) VALUES (?, ?, ?, ?)', d);

    // id, nom, client, budget, statut, service, proprietaire
    const projects = [
      [1, 'Refonte plateforme interne', 'Interne', 85000, 'En cours', 1, 4],
      [2, 'Migration paie', 'Interne', 40000, 'Termine', 2, 2],
      [3, 'Audit cloture Q3', 'Groupe Atrium Holding', 60000, 'En cours', 3, 3],
      [4, 'Portefeuille grands comptes Nord', 'ClientX SARL', 150000, 'En cours', 4, 5],
      [5, 'Durcissement securite SI', 'Interne', 95000, 'En cours', 5, 6],
    ];
    for (const pr of projects) {
      await t.run(
        'INSERT INTO projects (id, name, client, budget, status, department_id, owner_id) VALUES (?, ?, ?, ?, ?, ?, ?)', pr
      );
    }

    const members = [
      [1, 1, 'Developpeuse'], [1, 4, 'Lead technique'], [5, 4, 'Contributeur'],
      [2, 2, 'Pilote RH'], [3, 3, 'Controleuse'], [4, 5, 'Responsable'], [5, 6, 'Administrateur SI'],
    ];
    for (const m of members) await t.run('INSERT INTO project_members (project_id, user_id, role_on_project) VALUES (?, ?, ?)', m);

    // Certains documents sont confidentiels : visibles uniquement par les membres du
    // projet (et l'Administrateur) -- voir isDocVisible() dans routes/lab.js. C'est la
    // cible concrete de la demonstration UNION-based sur /api/search.
    const docs = [
      [1, 1, 'Specifications API interne', 0,
        'Document fonctionnel public : endpoints REST du portail collaborateur, pagination, formats de reponse.', 1],
      [2, 1, 'Grille de remuneration - equipe plateforme', 1,
        'CONFIDENTIEL. Alice Martin : 650 000 FCFA/mois. Julien Picard : 1 200 000 FCFA/mois. Revision prevue T1 2027.', 4],
      [3, 3, "Rapport d'audit cloture Q3 - confidentiel", 1,
        'CONFIDENTIEL. Ecart detecte sur le compte fournisseurs : 12,4 M FCFA. A regulariser avant le prochain CA.', 3],
      [4, 4, 'Grille tarifaire ClientX 2026', 1,
        'CONFIDENTIEL. Remise negociee ClientX SARL : -18% sur volume annuel. Clause de confidentialite stricte.', 5],
      [5, 5, 'Resultats du pentest interne', 1,
        'CONFIDENTIEL. Vulnerabilites critiques identifiees sur le portail RH. Correctif planifie sprint 14.', 6],
    ];
    for (const d of docs) {
      await t.run(
        'INSERT INTO documents (id, project_id, title, confidential, content, author_id) VALUES (?, ?, ?, ?, ?, ?)', d
      );
    }

    const logins = [
      [1, 1, '2026-09-28T08:12:00Z', '10.0.4.21', 1], [2, 1, '2026-10-01T08:05:00Z', '10.0.4.21', 1],
      [3, 4, '2026-10-01T07:58:00Z', '10.0.4.9', 1], [4, 3, '2026-09-30T14:40:00Z', '10.0.6.44', 1],
      [5, 6, '2026-10-02T09:00:00Z', '10.0.1.2', 1],
    ];
    for (const l of logins) await t.run('INSERT INTO login_history (id, user_id, ts, ip, success) VALUES (?, ?, ?, ?, ?)', l);
  });
}

async function init() {
  await p.run('PRAGMA foreign_keys = ON');
  await p.exec(SCHEMA);
  const { c } = await p.get('SELECT COUNT(*) AS c FROM users');
  if (c === 0) await seed();
}

db.p = p;
db.DEMO_PASSWORD = DEMO_PASSWORD;
db.ready = init();
module.exports = db;
