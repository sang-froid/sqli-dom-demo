// Droits d'acces et logique metier des routes d'ecriture : qui voit quoi, qui peut modifier quoi.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { start } = require('./helpers');

let t;
before(async () => { t = await start(); });
after(async () => { await t.close(); });

// ---------------------------------------------------------------- annuaire
test("l'annuaire est limite au perimetre de chaque profil", async () => {
  const count = async (who) => (await (await t.as(who)).get('/api/employees')).data.employees.length;
  assert.equal(await count('alice'), 1);   // collaboratrice : elle seule
  assert.equal(await count('julien'), 2);  // manager : lui + Alice
  assert.equal(await count('admin'), 6);
});

test('les services sont lisibles par un compte connecte uniquement', async () => {
  assert.equal((await t.anonymous().get('/api/departments')).status, 401);
  assert.equal((await (await t.as('alice')).get('/api/departments')).data.length, 5);
});

// ---------------------------------------------------------------- projets : visibilite
test('chacun ne voit que ses projets ; un admin les voit tous', async () => {
  const names = async (who) => (await (await t.as(who)).get('/api/projects')).data.projects.map((p) => p.id);
  assert.deepEqual(await names('alice'), [1]);
  assert.deepEqual((await names('julien')).sort(), [1, 5]);
  assert.equal((await names('admin')).length, 5);
});

test("ouvrir un projet dont on n'est pas membre est refuse (403)", async () => {
  const alice = await t.as('alice');
  assert.equal((await alice.get('/api/projects/3')).status, 403);
  assert.equal((await alice.get('/api/projects/1')).status, 200);
  assert.equal((await alice.get('/api/projects/999')).status, 404);
  assert.equal((await alice.get('/api/projects/abc')).status, 404);
});

// ---------------------------------------------------------------- projets : creation
test('creation de projet : reservee aux managers (dans leur service) et aux admins', async () => {
  const body = (department_id) => ({ name: 'Projet test', client: 'Interne', budget: 1000, status: 'En cours', department_id });

  assert.equal((await (await t.as('alice')).post('/api/projects', body(1))).status, 403, 'collaboratrice');
  const julien = await t.as('julien');
  assert.equal((await julien.post('/api/projects', body(2))).status, 403, 'autre service');
  const ok = await julien.post('/api/projects', body(1));
  assert.equal(ok.status, 201);
  assert.equal(ok.data.owner_id, 4);
  assert.equal(ok.data.member_count, 1, 'le createur devient membre');

  assert.equal((await (await t.as('admin')).post('/api/projects', body(2))).status, 201);
});

test('creation de projet : entrees invalides refusees', async () => {
  const julien = await t.as('julien');
  const base = { name: 'Valide', client: 'C', budget: 10, status: 'En cours', department_id: 1 };
  assert.equal((await julien.post('/api/projects', { ...base, name: '' })).status, 400);
  assert.equal((await julien.post('/api/projects', { ...base, budget: -5 })).status, 400);
  assert.equal((await julien.post('/api/projects', { ...base, status: 'Inconnu' })).status, 400);
  assert.equal((await julien.post('/api/projects', { ...base, department_id: 999 })).status, 400);
});

// ---------------------------------------------------------------- projets : gestion
test('seul le proprietaire (ou un admin) gere membres et projet', async () => {
  const alice = await t.as('alice');   // membre, pas proprietaire du projet 1
  const julien = await t.as('julien'); // proprietaire

  assert.equal((await alice.post('/api/projects/1/members', { user_id: 2, role_on_project: 'Testeur' })).status, 403);
  assert.equal((await alice.patch('/api/projects/1', { name: 'X', client: 'X', budget: 1, status: 'En cours', department_id: 1 })).status, 403);
  assert.equal((await alice.delete('/api/projects/1')).status, 403);

  assert.equal((await julien.post('/api/projects/1/members', { user_id: 2, role_on_project: 'Testeur' })).status, 201);
  assert.equal((await julien.post('/api/projects/1/members', { user_id: 2, role_on_project: 'Testeur' })).status, 409, 'doublon');
  assert.equal((await julien.post('/api/projects/1/members', { user_id: 999, role_on_project: 'X' })).status, 400);

  const detail = (await julien.get('/api/projects/1')).data;
  assert.equal(detail.members.length, 3);
  assert.equal(detail.permissions.can_manage, true);
  assert.equal((await alice.get('/api/projects/1')).data.permissions.can_manage, false);

  assert.equal((await julien.delete('/api/projects/1/members/4')).status, 400, 'le proprietaire reste');
  assert.equal((await julien.delete('/api/projects/1/members/2')).status, 200);
  assert.equal((await julien.delete('/api/projects/1/members/2')).status, 404);

  const upd = await julien.patch('/api/projects/1', { name: 'Refonte v2', client: 'Interne', budget: 90000, status: 'Suspendu', department_id: 1 });
  assert.equal(upd.status, 200);
  assert.equal(upd.data.status, 'Suspendu');
});

test('un tiers ne peut pas lister les candidats ni gerer un projet auquel il est etranger', async () => {
  const nadia = await t.as('nadia');
  assert.equal((await nadia.get('/api/projects/1/candidates')).status, 403);
  assert.equal((await nadia.post('/api/projects/1/members', { user_id: 3, role_on_project: 'X' })).status, 403);
});

test('suppression de projet : cascade sur membres et documents', async () => {
  const julien = await t.as('julien');
  const { data: p } = await julien.post('/api/projects', { name: 'A supprimer', client: 'C', budget: 1, status: 'En cours', department_id: 1 });
  await julien.post(`/api/projects/${p.id}/documents`, { title: 'D', content: 'c' });
  assert.equal((await julien.delete(`/api/projects/${p.id}`)).status, 200);
  assert.equal((await julien.get(`/api/projects/${p.id}`)).status, 404);
});

// ---------------------------------------------------------------- documents
test('documents : creation par un membre, edition par auteur / proprietaire / admin', async () => {
  const alice = await t.as('alice');
  const julien = await t.as('julien');
  const bassirou = await t.as('bassirou');
  const nadia = await t.as('nadia');

  const created = await alice.post('/api/projects/1/documents', { title: 'Compte rendu', content: 'RAS', confidential: true });
  assert.equal(created.status, 201);
  const id = created.data.id;

  assert.equal((await bassirou.post('/api/projects/1/documents', { title: 'X', content: 'x' })).status, 403, 'non membre');

  const asAlice = (await alice.get('/api/projects/1')).data.documents.find((d) => d.id === id);
  assert.equal(asAlice.can_edit, true);
  assert.equal(asAlice.confidential, true);

  assert.equal((await julien.patch(`/api/documents/${id}`, { title: 'Compte rendu v2', content: 'Modifie', confidential: false })).status, 200);
  assert.equal((await nadia.patch(`/api/documents/${id}`, { title: 'Pirate', content: 'x' })).status, 404, "meme reponse qu'un document inexistant");
  assert.equal((await nadia.delete(`/api/documents/${id}`)).status, 404);

  // membre non auteur et non proprietaire : lecture seule
  await julien.post('/api/projects/1/members', { user_id: 2, role_on_project: 'Relecteur' });
  const bassirouDoc = (await bassirou.get('/api/projects/1')).data.documents.find((d) => d.id === id);
  assert.equal(bassirouDoc.can_edit, false);
  assert.equal((await bassirou.patch(`/api/documents/${id}`, { title: 'x', content: 'x' })).status, 403);

  assert.equal((await alice.delete(`/api/documents/${id}`)).status, 200);
  assert.equal((await alice.delete(`/api/documents/${id}`)).status, 404);
});

test('documents : entrees invalides refusees', async () => {
  const alice = await t.as('alice');
  assert.equal((await alice.post('/api/projects/1/documents', { title: '', content: 'x' })).status, 400);
  assert.equal((await alice.post('/api/projects/1/documents', { title: 'ok', content: 'x', confidential: 'oui' })).status, 400);
  assert.equal((await alice.post('/api/projects/1/documents', { title: 'ok', content: 'x'.repeat(5001) })).status, 400);
});

// ---------------------------------------------------------------- mon profil
test('chacun peut modifier ses coordonnees, pas son role ni son service', async () => {
  const alice = await t.as('alice');
  const r = await alice.patch('/api/me', { email: 'alice.nouvelle@atrium.test', phone: '+229 00 00 00 00', site: 'Cotonou', bio: 'Nouvelle bio', role: 'Administrateur', department: 'Finance' });
  assert.equal(r.status, 200);
  assert.equal(r.data.user.bio, 'Nouvelle bio');
  assert.equal(r.data.user.role, 'Collaborateur');
  assert.equal(r.data.user.department, 'Ingenierie');
  assert.equal((await alice.get('/api/admin/users')).status, 403, "pas d'elevation de privilege");

  assert.equal((await alice.patch('/api/me', { email: 'pas-un-email' })).status, 400);
  assert.equal((await alice.patch('/api/me', { email: 'admin@atrium.test' })).status, 409, 'e-mail deja pris');
});

// ---------------------------------------------------------------- administration
test("l'administration est interdite aux non-admins (403) et aux anonymes (401)", async () => {
  for (const path of ['/api/admin/users', '/api/admin/audit', '/api/admin/logins']) {
    assert.equal((await (await t.as('julien')).get(path)).status, 403, path);
    assert.equal((await t.anonymous().get(path)).status, 401, path);
  }
  assert.equal((await (await t.as('julien')).post('/api/admin/users', {})).status, 403);
});

test('creation de compte : validations, doublons, connexion possible ensuite', async () => {
  const admin = await t.as('admin');
  const valid = {
    full_name: 'Carine Adjovi', username: 'carine.adjovi', email: 'carine.adjovi@atrium.test',
    department: 'Finance', role: 'Collaborateur', manager_id: 3, password: 'Mdp-Carine-2026',
  };
  assert.equal((await admin.post('/api/admin/users', { ...valid, password: 'court' })).status, 400);
  assert.equal((await admin.post('/api/admin/users', { ...valid, username: 'a b' })).status, 400);
  assert.equal((await admin.post('/api/admin/users', { ...valid, department: 'Inconnu' })).status, 400);
  assert.equal((await admin.post('/api/admin/users', { ...valid, manager_id: 999 })).status, 400);

  const ok = await admin.post('/api/admin/users', valid);
  assert.equal(ok.status, 201);
  assert.equal('password' in ok.data, false);
  assert.equal((await admin.post('/api/admin/users', valid)).status, 409, 'doublon');

  assert.equal((await t.anonymous().login('carine.adjovi', 'Mdp-Carine-2026')).status, 200);

  // son manager (Nadia) la voit maintenant dans son annuaire
  const nadia = await t.as('nadia');
  assert.equal((await nadia.get('/api/employees')).data.employees.length, 2);
  assert.equal((await nadia.get('/api/me')).data.user.is_manager, true);
});

test('modification de compte : hierarchie sans cycle, dernier admin protege', async () => {
  const admin = await t.as('admin');
  const users = (await admin.get('/api/admin/users')).data;
  const id = (u) => users.find((x) => x.username === u).id;

  // Alice a pour manager Julien : faire de Julien un subordonne d'Alice creerait un cycle.
  assert.equal((await admin.patch(`/api/admin/users/${id('julien.picard')}`, { manager_id: id('alice.martin') })).status, 400);
  assert.equal((await admin.patch(`/api/admin/users/${id('alice.martin')}`, { manager_id: id('alice.martin') })).status, 400);

  assert.equal((await admin.patch(`/api/admin/users/${id('admin')}`, { active: false })).status, 409, 'pas de sa propre desactivation');
  assert.equal((await admin.patch(`/api/admin/users/${id('admin')}`, { role: 'Collaborateur' })).status, 409, 'dernier administrateur');
  assert.equal((await admin.patch(`/api/admin/users/${id('admin')}`, {})).status, 400, 'rien a modifier');
  assert.equal((await admin.patch('/api/admin/users/999', { bio: 'x' })).status, 404);

  const r = await admin.patch(`/api/admin/users/${id('alice.martin')}`, { role: 'Developpeuse senior', phone: '' });
  assert.equal(r.status, 200);
  assert.equal(r.data.role, 'Developpeuse senior');
});

test('reinitialisation de mot de passe par un admin', async () => {
  const admin = await t.as('admin');
  const victim = await t.as('julien');
  const id = (await admin.get('/api/admin/users')).data.find((u) => u.username === 'julien.picard').id;

  assert.equal((await admin.post(`/api/admin/users/${id}/password`, { password: 'faible' })).status, 400);
  assert.equal((await admin.post(`/api/admin/users/${id}/password`, { password: 'Reset-Julien-2026' })).status, 200);
  assert.equal((await victim.get('/api/me')).status, 401, 'ses sessions sont fermees');
  assert.equal((await t.anonymous().login('julien.picard', 'Reset-Julien-2026')).status, 200);
});

test('services : creation, renommage repercute sur les comptes, suppression refusee si utilise', async () => {
  const admin = await t.as('admin');
  const created = await admin.post('/api/admin/departments', { name: 'Juridique', budget: 50000, location: 'Cotonou' });
  assert.equal(created.status, 201);
  assert.equal((await admin.post('/api/admin/departments', { name: 'Juridique', budget: 1, location: 'X' })).status, 409);

  const ing = (await admin.get('/api/departments')).data.find((d) => d.name === 'Ingenierie');
  assert.equal((await admin.delete(`/api/admin/departments/${ing.id}`)).status, 409, 'des comptes y sont rattaches');

  assert.equal((await admin.patch(`/api/admin/departments/${created.data.id}`, { name: 'Affaires juridiques', budget: 60000, location: 'Cotonou' })).status, 200);
  assert.equal((await admin.delete(`/api/admin/departments/${created.data.id}`)).status, 200);

  const renamed = await admin.patch(`/api/admin/departments/${ing.id}`, { name: 'Ingenierie logicielle', budget: ing.budget, location: ing.location });
  assert.equal(renamed.status, 200);
  const alice = (await admin.get('/api/admin/users')).data.find((u) => u.username === 'alice.martin');
  assert.equal(alice.department, 'Ingenierie logicielle');
});

test("le journal d'audit trace les ecritures sans jamais contenir de mot de passe", async () => {
  const admin = await t.as('admin');
  await admin.post(`/api/admin/users/3/password`, { password: 'Admin-Nouveau-2026' });
  const log = (await admin.get('/api/admin/audit?limit=500')).data;
  const actions = new Set(log.map((e) => e.action));
  for (const a of ['user_create', 'project_create', 'member_add', 'document_create', 'password_reset']) {
    assert.ok(actions.has(a), `action ${a} journalisee`);
  }
  assert.equal(JSON.stringify(log).includes('Admin-Nouveau-2026'), false);
  assert.equal(JSON.stringify(log).includes('Mdp-Carine-2026'), false);
});

test("l'API repond 404 JSON sur une route inconnue", async () => {
  const r = await (await t.as('alice')).get('/api/nexiste-pas');
  assert.equal(r.status, 404);
  assert.ok(r.data.error);
});
