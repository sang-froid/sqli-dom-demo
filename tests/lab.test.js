// Non-regression du LABO : les deux surfaces vulnerables doivent le rester en mode
// "vulnerable" (c'est le sujet du cours) et etre closes en mode "secure". Si l'un de ces
// tests casse, c'est la demonstration de soutenance qui est cassee.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { start } = require('./helpers');

let t, alice;
before(async () => { t = await start(); alice = await t.as('alice'); });
after(async () => { await t.close(); });

const profile = (client, id, mode) => client.get(`/api/profile?id=${encodeURIComponent(id)}&mode=${mode}`);
const search = (client, q, mode, extra = '') => client.get(`/api/search?mode=${mode}&q=${encodeURIComponent(q)}${extra}`);

// ---------------------------------------------------------------- /api/profile
test('profile / vulnerable : sa propre fiche et acces hors perimetre bloque par le filtre', async () => {
  assert.deepEqual((await profile(alice, '1', 'vulnerable')).data.resultats.map((r) => r.id), [1]);
  assert.deepEqual((await profile(alice, '3', 'vulnerable')).data.resultats, [], 'filtre actif sans injection');
});

test("profile / vulnerable : '3 -- ' supprime le filtre d'autorisation (fiche de Nadia)", async () => {
  const r = await profile(alice, '3 -- ', 'vulnerable');
  assert.equal(r.data.resultats.length, 1);
  assert.equal(r.data.resultats[0].full_name, 'Nadia Benali');
  assert.match(r.data.sql_execute, /--/);
});

test("profile / vulnerable : '0 OR 1=1 -- ' renvoie toutes les fiches, hashs inclus", async () => {
  const r = await profile(alice, '0 OR 1=1 -- ', 'vulnerable');
  assert.equal(r.data.resultats.length, 6);
  assert.ok(r.data.resultats.every((u) => /^\$2[aby]\$/.test(u.password)));
});

test('profile / vulnerable : le niveau document tient meme apres contournement (defense en profondeur)', async () => {
  const r = await profile(alice, '3 -- ', 'vulnerable');
  const docs = r.data.projects.flatMap((p) => p.documents);
  assert.ok(docs.length > 0);
  assert.ok(docs.every((d) => d.hidden && d.content === null));
});

test('profile / vulnerable : une erreur SQL brute est renvoyee (CWE-209, volontaire)', async () => {
  const r = await profile(alice, "1'", 'vulnerable');
  assert.equal(r.status, 500);
  assert.match(r.data.error, /syntax|unrecognized/i);
});

test('profile / secure : format invalide rejete, fiche hors perimetre refusee, fiche autorisee servie', async () => {
  const injected = await profile(alice, '0 OR 1=1 -- ', 'secure');
  assert.equal(injected.status, 400);
  assert.deepEqual(injected.data.resultats, []);

  const outside = await profile(alice, '3', 'secure');
  assert.equal(outside.status, 403);
  assert.deepEqual(outside.data.resultats, []);

  const own = await profile(alice, '1', 'secure');
  assert.equal(own.status, 200);
  assert.equal(own.data.resultats[0].id, 1);
});

test("profile / secure : un manager voit ses subordonnes, un admin voit tout", async () => {
  const julien = await t.as('julien');
  assert.equal((await profile(julien, '1', 'secure')).status, 200);
  assert.equal((await profile(julien, '3', 'secure')).status, 403);
  assert.equal((await profile(await t.as('admin'), '3', 'secure')).status, 200);
});

test('profile : le mode par defaut (non precise) est le mode vulnerable', async () => {
  const r = await alice.get(`/api/profile?id=${encodeURIComponent('3 -- ')}`);
  assert.equal(r.data.mode, 'vulnerable');
  assert.equal(r.data.resultats.length, 1);
});

// ---------------------------------------------------------------- /api/search
const UNION = "zzz%' UNION SELECT id, title, 'Document confidentiel', 'N/A', NULL FROM documents WHERE confidential = 1 -- ";

test("search / vulnerable : UNION SELECT exfiltre les documents confidentiels d'autres tables", async () => {
  const r = await search(alice, UNION, 'vulnerable');
  assert.equal(r.status, 200);
  assert.equal(r.data.resultats.length, 4);
  const titles = r.data.resultats.map((x) => x.full_name).join(' | ');
  assert.match(titles, /Grille de remuneration/);
  assert.match(titles, /pentest/);
  assert.ok(r.data.resultats.every((x) => x.role === 'Document confidentiel'));
});

test('search / vulnerable : recherche normale limitee au perimetre', async () => {
  const r = await search(alice, 'a', 'vulnerable');
  assert.deepEqual(r.data.resultats.map((x) => x.id), [1]);
});

test('search / vulnerable : les filtres service et statut sont aussi concatenes', async () => {
  const r = await alice.get(`/api/search?mode=vulnerable&department=${encodeURIComponent("x' OR '1'='1")}`);
  assert.equal(r.status, 200);
  assert.deepEqual(r.data.resultats.map((x) => x.id), [1], "l'autorisation finale reste appliquee");
});

test("search / secure : la meme chaine est traitee comme une donnee", async () => {
  const r = await search(alice, UNION, 'secure');
  assert.equal(r.status, 200);
  assert.deepEqual(r.data.resultats, []);
  assert.doesNotMatch(r.data.sql_execute, /UNION/i);
});

test('search / secure : recherche legitime, filtres service/statut et perimetre', async () => {
  assert.deepEqual((await search(alice, 'a', 'secure')).data.resultats.map((x) => x.id), [1]);
  assert.deepEqual((await search(alice, '', 'secure', '&status=En%20cours')).data.resultats.map((x) => x.id), [1]);
  assert.deepEqual((await search(alice, '', 'secure', '&status=Termine')).data.resultats, []);
  assert.equal((await search(await t.as('admin'), '', 'secure')).data.resultats.length, 6);
});

// ---------------------------------------------------------------- journalisation / forensique
test("les requetes vulnerables sont journalisees pour l'analyse forensique", async () => {
  const fs = require('node:fs');
  const path = require('node:path');
  await profile(alice, '0 OR 1=1 -- ', 'vulnerable');
  await new Promise((r) => setTimeout(r, 100)); // laisse le flux d'ecriture se vider
  const log = fs.readFileSync(path.join(process.env.LOG_DIR, 'requests.jsonl'), 'utf8');
  assert.match(log, /OR 1=1/);
  assert.match(log, /UNION SELECT/i);
});
