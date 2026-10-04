const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { start, ACCOUNTS, db } = require('./helpers');

let t;
before(async () => { t = await start(); });
after(async () => { await t.close(); });

test('une route protegee sans session repond 401', async () => {
  const r = await t.anonymous().get('/api/me');
  assert.equal(r.status, 401);
});

test("l'ancien parametre ?as= n'ouvre plus aucune session", async () => {
  const r = await t.anonymous().get('/api/employees?as=6');
  assert.equal(r.status, 401);
  const p = await t.anonymous().get('/api/profile?id=1&as=6&mode=vulnerable');
  assert.equal(p.status, 401);
});

test('connexion : cookie HttpOnly/SameSite, jamais de hash dans la reponse', async () => {
  const c = t.anonymous();
  const [u, p] = ACCOUNTS.alice;
  const r = await c.login(u, p);
  assert.equal(r.status, 200);
  const cookie = r.headers.get('set-cookie');
  assert.match(cookie, /atrium_sid=[0-9a-f]{64}/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);
  assert.equal(r.data.user.username, 'alice.martin');
  assert.equal('password' in r.data.user, false);

  const me = await c.get('/api/me');
  assert.equal(me.status, 200);
  assert.equal(me.data.user.is_admin, false);
  assert.equal('password' in me.data.user, false);
});

test("seule l'empreinte du jeton est stockee en base", async () => {
  const c = await t.as('fatou');
  const token = c.cookie.split('=')[1];
  const raw = await db.p.get('SELECT 1 AS ok FROM sessions WHERE id = ?', [token]);
  assert.equal(raw, undefined);
});

test('mauvais mot de passe et identifiant inconnu : meme message generique', async () => {
  const a = await t.anonymous().login('alice.martin', 'mauvais-mot-de-passe');
  const b = await t.anonymous().login('personne.inconnu', 'mauvais-mot-de-passe');
  assert.equal(a.status, 401);
  assert.equal(b.status, 401);
  assert.equal(a.data.error, b.data.error);
});

test('une injection SQL dans le formulaire de connexion est inoperante', async () => {
  const r = await t.anonymous().login("admin' OR '1'='1' --", 'x');
  assert.equal(r.status, 401);
});

test('deconnexion : la session est detruite cote serveur', async () => {
  const c = await t.as('alice');
  const stolen = c.cookie;
  assert.equal((await c.post('/api/auth/logout')).status, 200);
  const replay = t.anonymous();
  replay.cookie = stolen;
  assert.equal((await replay.get('/api/me')).status, 401);
});

test('une ecriture sans en-tete anti-CSRF est refusee', async () => {
  const c = await t.as('alice');
  const r = await fetch(`${t.base}/api/me`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Cookie: c.cookie },
    body: JSON.stringify({ email: 'x@y.test' }),
  });
  assert.equal(r.status, 403);
});

test('limitation des essais : 429 apres 5 echecs, meme avec le bon mot de passe', async () => {
  const c = t.anonymous();
  for (let i = 0; i < 5; i++) assert.equal((await c.login('nadia.benali', 'faux')).status, 401);
  const [, good] = ACCOUNTS.nadia;
  const r = await c.login('nadia.benali', good);
  assert.equal(r.status, 429);
  assert.ok(Number(r.headers.get('retry-after')) > 0);
  // un autre identifiant n'est pas affecte
  assert.equal((await t.anonymous().login(...ACCOUNTS.fatou)).status, 200);
});

test('les connexions (reussies ou non) sont historisees', async () => {
  const c = await t.as('julien');
  const { data } = await c.get('/api/me/logins');
  assert.ok(data.logins.length >= 1);
  await t.anonymous().login('julien.picard', 'faux');
  const after = (await c.get('/api/me/logins')).data.logins;
  assert.ok(after.some((l) => l.success === 0));
  const failed = await db.p.get("SELECT 1 AS ok FROM audit_log WHERE action = 'login_failed'");
  assert.ok(failed, "les echecs de connexion sont aussi dans le journal d'audit");
});

test('changement de mot de passe : verifications, effet, sessions des autres appareils fermees', async () => {
  const device1 = await t.as('bassirou');
  const device2 = await t.as('bassirou');

  assert.equal((await device1.post('/api/me/password', { current: 'faux', next: 'Nouveau-Mdp-2026' })).status, 403);
  assert.equal((await device1.post('/api/me/password', { current: ACCOUNTS.bassirou[1], next: 'court1' })).status, 400);
  assert.equal((await device1.post('/api/me/password', { current: ACCOUNTS.bassirou[1], next: 'uniquementdeslettres' })).status, 400);

  assert.equal((await device1.post('/api/me/password', { current: ACCOUNTS.bassirou[1], next: 'Nouveau-Mdp-2026' })).status, 200);
  assert.equal((await device1.get('/api/me')).status, 200, 'la session courante survit');
  assert.equal((await device2.get('/api/me')).status, 401, "l'autre appareil est deconnecte");

  assert.equal((await t.anonymous().login('bassirou.koffi', ACCOUNTS.bassirou[1])).status, 401);
  assert.equal((await t.anonymous().login('bassirou.koffi', 'Nouveau-Mdp-2026')).status, 200);
});

test('un compte desactive ne peut plus se connecter et sa session meurt aussitot', async () => {
  const admin = await t.as('admin');
  const victim = await t.as('fatou');
  assert.equal((await victim.get('/api/me')).status, 200);

  const users = (await admin.get('/api/admin/users')).data;
  const fatou = users.find((u) => u.username === 'fatou.diarra');
  assert.equal((await admin.patch(`/api/admin/users/${fatou.id}`, { active: false })).status, 200);

  assert.equal((await victim.get('/api/me')).status, 401);
  assert.equal((await t.anonymous().login(...ACCOUNTS.fatou)).status, 401);

  await admin.patch(`/api/admin/users/${fatou.id}`, { active: true });
  assert.equal((await t.anonymous().login(...ACCOUNTS.fatou)).status, 200);
});

test('les comptes de demo sont exposes seulement quand DEMO_ACCOUNTS est actif', async () => {
  const r = await t.anonymous().get('/api/demo-accounts');
  assert.equal(r.status, 200);
  assert.equal(r.data.length, 6);
});
