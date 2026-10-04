// Projets, membres et documents. Toutes les requetes sont parametrees.
//
// Qui peut quoi :
//   - voir un projet            : ses membres, son proprietaire, les administrateurs
//   - creer un projet           : administrateur, ou manager dans SON service
//   - modifier / supprimer /
//     gerer les membres         : proprietaire du projet ou administrateur
//   - ajouter un document       : tout membre (le proprietaire est membre d'office)
//   - modifier / supprimer un
//     document                  : son auteur, le proprietaire du projet, un administrateur

const express = require('express');
const db = require('../db');
const v = require('../lib/validate');
const { HttpError, wrap } = require('../lib/http');
const {
  isAdmin, canManageProject, canAccessProject, canEditDocument, requireAuth,
} = require('../lib/authz');
const { audit } = require('../lib/audit');

const router = express.Router();
router.use(requireAuth);

const STATUSES = ['En cours', 'Termine', 'Suspendu'];
const PROJECT_SQL = `
  SELECT p.id, p.name, p.client, p.budget, p.status, p.department_id, p.owner_id, p.created_at,
         d.name AS department_name, o.full_name AS owner_name,
         (SELECT COUNT(*) FROM project_members pm WHERE pm.project_id = p.id) AS member_count
  FROM projects p
  JOIN departments d ON d.id = p.department_id
  LEFT JOIN users o ON o.id = p.owner_id`;

async function loadProject(id) {
  const project = await db.p.get(`${PROJECT_SQL} WHERE p.id = ?`, [id]);
  if (!project) throw new HttpError(404, 'Projet introuvable.');
  return project;
}

async function loadAccessibleProject(req) {
  const project = await loadProject(v.idParam(req));
  if (!(await canAccessProject(req.user, project))) throw new HttpError(403, 'Acces refuse : vous ne participez pas a ce projet.');
  return project;
}

async function loadManageableProject(req) {
  const project = await loadAccessibleProject(req);
  if (!canManageProject(req.user, project)) throw new HttpError(403, 'Action reservee au proprietaire du projet ou a un administrateur.');
  return project;
}

function projectInput(b) {
  return {
    name: v.string(b, 'name', 'Le nom du projet', { min: 2, max: 120 }),
    client: v.string(b, 'client', 'Le client', { max: 120 }),
    budget: v.int(b, 'budget', 'Le budget', { min: 0 }),
    status: v.oneOf(b, 'status', 'Le statut', STATUSES),
    department_id: v.int(b, 'department_id', 'Le service', { min: 1 }),
  };
}

const permissionsFor = (user, project) => ({
  can_manage: canManageProject(user, project),
  can_add_document: true, // acces au projet <=> membre, proprietaire ou admin
});

// ------------------------------------------------------------------ projets
router.get('/projects', wrap(async (req, res) => {
  const rows = isAdmin(req.user)
    ? await db.p.all(`${PROJECT_SQL} ORDER BY p.name`)
    : await db.p.all(
      `${PROJECT_SQL}
       WHERE p.owner_id = ? OR p.id IN (SELECT project_id FROM project_members WHERE user_id = ?)
       ORDER BY p.name`, [req.user.id, req.user.id]);
  res.json({
    projects: rows,
    can_create: isAdmin(req.user) || !!req.user.is_manager,
  });
}));

router.post('/projects', wrap(async (req, res) => {
  if (!isAdmin(req.user) && !req.user.is_manager) {
    throw new HttpError(403, 'Seuls les managers et les administrateurs peuvent creer un projet.');
  }
  const data = projectInput(req.body || {});
  const dept = await db.p.get('SELECT id, name FROM departments WHERE id = ?', [data.department_id]);
  if (!dept) throw new HttpError(400, 'Service inconnu.');
  if (!isAdmin(req.user) && dept.name !== req.user.department) {
    throw new HttpError(403, 'Un manager ne peut creer un projet que dans son propre service.');
  }

  const id = await db.p.tx(async (t) => {
    const { lastID } = await t.run(
      'INSERT INTO projects (name, client, budget, status, department_id, owner_id) VALUES (?, ?, ?, ?, ?, ?)',
      [data.name, data.client, data.budget, data.status, data.department_id, req.user.id]);
    await t.run('INSERT INTO project_members (project_id, user_id, role_on_project) VALUES (?, ?, ?)',
      [lastID, req.user.id, 'Responsable']);
    return lastID;
  });
  await audit(req.user.id, 'project_create', 'project', id, data);
  res.status(201).json(await loadProject(id));
}));

router.get('/projects/:id', wrap(async (req, res) => {
  const project = await loadAccessibleProject(req);
  const members = await db.p.all(
    `SELECT pm.user_id, pm.role_on_project, u.full_name, u.department, u.role
     FROM project_members pm JOIN users u ON u.id = pm.user_id
     WHERE pm.project_id = ? ORDER BY u.full_name`, [project.id]);
  const documents = await db.p.all(
    `SELECT d.id, d.title, d.confidential, d.content, d.author_id, d.created_at, d.updated_at,
            a.full_name AS author_name
     FROM documents d LEFT JOIN users a ON a.id = d.author_id
     WHERE d.project_id = ? ORDER BY d.created_at DESC, d.id DESC`, [project.id]);
  res.json({
    project,
    members,
    documents: documents.map((d) => ({
      ...d,
      confidential: !!d.confidential,
      can_edit: canEditDocument(req.user, d, project),
    })),
    permissions: permissionsFor(req.user, project),
  });
}));

router.patch('/projects/:id', wrap(async (req, res) => {
  const project = await loadManageableProject(req);
  const data = projectInput(req.body || {});
  if (!(await db.p.get('SELECT 1 AS ok FROM departments WHERE id = ?', [data.department_id]))) {
    throw new HttpError(400, 'Service inconnu.');
  }
  await db.p.run('UPDATE projects SET name = ?, client = ?, budget = ?, status = ?, department_id = ? WHERE id = ?',
    [data.name, data.client, data.budget, data.status, data.department_id, project.id]);
  await audit(req.user.id, 'project_update', 'project', project.id, data);
  res.json(await loadProject(project.id));
}));

router.delete('/projects/:id', wrap(async (req, res) => {
  const project = await loadManageableProject(req);
  await db.p.tx(async (t) => {
    await t.run('DELETE FROM documents WHERE project_id = ?', [project.id]);
    await t.run('DELETE FROM project_members WHERE project_id = ?', [project.id]);
    await t.run('DELETE FROM projects WHERE id = ?', [project.id]);
  });
  await audit(req.user.id, 'project_delete', 'project', project.id, project.name);
  res.json({ ok: true });
}));

// ------------------------------------------------------------------ membres
// Comptes actifs qui ne sont pas encore membres : pour le selecteur d'ajout.
router.get('/projects/:id/candidates', wrap(async (req, res) => {
  const project = await loadManageableProject(req);
  res.json(await db.p.all(
    `SELECT id, full_name, department FROM users
     WHERE active = 1 AND id NOT IN (SELECT user_id FROM project_members WHERE project_id = ?)
     ORDER BY full_name`, [project.id]));
}));

router.post('/projects/:id/members', wrap(async (req, res) => {
  const project = await loadManageableProject(req);
  const b = req.body || {};
  const userId = v.int(b, 'user_id', 'Le collaborateur', { min: 1 });
  const role = v.string(b, 'role_on_project', 'Le role sur le projet', { max: 60 });
  const user = await db.p.get('SELECT id, active FROM users WHERE id = ?', [userId]);
  if (!user || !user.active) throw new HttpError(400, 'Collaborateur inconnu ou desactive.');
  if (await db.p.get('SELECT 1 AS ok FROM project_members WHERE project_id = ? AND user_id = ?', [project.id, userId])) {
    throw new HttpError(409, 'Ce collaborateur est deja membre du projet.');
  }
  await db.p.run('INSERT INTO project_members (project_id, user_id, role_on_project) VALUES (?, ?, ?)', [project.id, userId, role]);
  await audit(req.user.id, 'member_add', 'project', project.id, { user_id: userId, role });
  res.status(201).json({ ok: true });
}));

router.delete('/projects/:id/members/:userId', wrap(async (req, res) => {
  const project = await loadManageableProject(req);
  const userId = v.idParam(req, 'userId');
  if (userId === project.owner_id) throw new HttpError(400, 'Le proprietaire ne peut pas etre retire du projet.');
  const { changes } = await db.p.run('DELETE FROM project_members WHERE project_id = ? AND user_id = ?', [project.id, userId]);
  if (!changes) throw new HttpError(404, 'Ce collaborateur n\'est pas membre du projet.');
  await audit(req.user.id, 'member_remove', 'project', project.id, { user_id: userId });
  res.json({ ok: true });
}));

// ------------------------------------------------------------------ documents
function documentInput(b) {
  return {
    title: v.string(b, 'title', 'Le titre', { max: 150 }),
    content: v.string(b, 'content', 'Le contenu', { max: 5000 }),
    confidential: v.bool(b, 'confidential', false) ? 1 : 0,
  };
}

router.post('/projects/:id/documents', wrap(async (req, res) => {
  const project = await loadAccessibleProject(req);
  const d = documentInput(req.body || {});
  const { lastID } = await db.p.run(
    'INSERT INTO documents (project_id, title, confidential, content, author_id, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    [project.id, d.title, d.confidential, d.content, req.user.id, new Date().toISOString()]);
  await audit(req.user.id, 'document_create', 'document', lastID, { project_id: project.id, confidential: !!d.confidential });
  res.status(201).json({ id: lastID });
}));

async function loadEditableDocument(req) {
  const doc = await db.p.get('SELECT * FROM documents WHERE id = ?', [v.idParam(req)]);
  if (!doc) throw new HttpError(404, 'Document introuvable.');
  const project = await loadProject(doc.project_id);
  // Meme message qu'un document inexistant si le compte n'a pas acces au projet :
  // on ne confirme pas l'existence d'un document confidentiel a un tiers.
  if (!(await canAccessProject(req.user, project))) throw new HttpError(404, 'Document introuvable.');
  if (!canEditDocument(req.user, doc, project)) {
    throw new HttpError(403, 'Seuls l\'auteur, le proprietaire du projet ou un administrateur peuvent modifier ce document.');
  }
  return doc;
}

router.patch('/documents/:id', wrap(async (req, res) => {
  const doc = await loadEditableDocument(req);
  const d = documentInput(req.body || {});
  await db.p.run('UPDATE documents SET title = ?, content = ?, confidential = ?, updated_at = ? WHERE id = ?',
    [d.title, d.content, d.confidential, new Date().toISOString(), doc.id]);
  await audit(req.user.id, 'document_update', 'document', doc.id, { confidential: !!d.confidential });
  res.json({ ok: true });
}));

router.delete('/documents/:id', wrap(async (req, res) => {
  const doc = await loadEditableDocument(req);
  await db.p.run('DELETE FROM documents WHERE id = ?', [doc.id]);
  await audit(req.user.id, 'document_delete', 'document', doc.id, doc.title);
  res.json({ ok: true });
}));

module.exports = router;
