// Regles d'autorisation applicatives, centralisees.
//
// Trois profils de compte :
//   - Administrateur (users.role = 'Administrateur') : voit et gere tout.
//   - Manager : tout compte ayant au moins un subordonne direct actif (calcule a chaque
//     requete, pas stocke) ; peut creer des projets dans son service.
//   - Collaborateur : tous les autres.
// Un compte est en plus "proprietaire" des projets dont il est owner_id : il les gere
// (membres, statut, suppression) sans etre administrateur.
// Un document est modifiable par son auteur, le proprietaire du projet ou un admin.

const db = require('../db');
const { HttpError } = require('./http');

const isAdmin = (user) => !!user && user.role === 'Administrateur';

async function isProjectMember(userId, projectId) {
  const row = await db.p.get('SELECT 1 AS ok FROM project_members WHERE project_id = ? AND user_id = ?', [projectId, userId]);
  return !!row;
}

const canManageProject = (user, project) => isAdmin(user) || project.owner_id === user.id;

async function canAccessProject(user, project) {
  return canManageProject(user, project) || isProjectMember(user.id, project.id);
}

const canEditDocument = (user, doc, project) =>
  isAdmin(user) || doc.author_id === user.id || project.owner_id === user.id;

function requireAuth(req, res, next) {
  if (!req.user) return next(new HttpError(401, 'Aucune session. Reconnectez-vous.'));
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user) return next(new HttpError(401, 'Aucune session. Reconnectez-vous.'));
  if (!isAdmin(req.user)) return next(new HttpError(403, 'Reserve aux administrateurs.'));
  next();
}

module.exports = {
  isAdmin, isProjectMember, canManageProject, canAccessProject, canEditDocument,
  requireAuth, requireAdmin,
};
