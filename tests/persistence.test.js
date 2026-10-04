// Persistance : la base est un fichier ; un redemarrage conserve les donnees et ne
// re-insere pas les donnees de demonstration. Chaque "demarrage" est un vrai processus Node.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.join(__dirname, '..');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'atrium-persist-'));
const dbFile = path.join(dir, 'atrium.db');

function run(script) {
  const out = execFileSync(process.execPath, ['-e', `
    const db = require('./db');
    (async () => { await db.ready; ${script} await new Promise(r => db.close(r)); })()
      .catch(e => { console.error(e); process.exit(1); });
  `], {
    cwd: root,
    env: { ...process.env, DB_PATH: dbFile, BCRYPT_ROUNDS: '4', LOG_DIR: dir },
    encoding: 'utf8',
  });
  return out.trim();
}

test('premier demarrage : le fichier est cree et seede', () => {
  const out = run("console.log(JSON.stringify(await db.p.get('SELECT COUNT(*) AS n FROM users')));");
  assert.equal(JSON.parse(out).n, 6);
  assert.ok(fs.existsSync(dbFile));
});

test('redemarrage : les modifications survivent et le seed ne rejoue pas', () => {
  run("await db.p.run(\"UPDATE users SET bio = 'persistee' WHERE id = 1\"); await db.p.run(\"DELETE FROM project_members WHERE project_id = 2\");");
  const out = run(`
    const u = await db.p.get('SELECT COUNT(*) AS n FROM users');
    const bio = await db.p.get('SELECT bio FROM users WHERE id = 1');
    const m = await db.p.get('SELECT COUNT(*) AS n FROM project_members WHERE project_id = 2');
    console.log(JSON.stringify({ users: u.n, bio: bio.bio, members: m.n }));
  `);
  assert.deepEqual(JSON.parse(out), { users: 6, bio: 'persistee', members: 0 });
});

test('DB_PATH=:memory: donne une base jetable', () => {
  const out = execFileSync(process.execPath, ['-e', `
    const db = require('./db');
    db.ready.then(async () => {
      await db.p.run("UPDATE users SET bio = 'ephemere' WHERE id = 1");
      console.log((await db.p.get('SELECT bio FROM users WHERE id = 1')).bio);
      db.close();
    });
  `], { cwd: root, env: { ...process.env, DB_PATH: ':memory:', BCRYPT_ROUNDS: '4', LOG_DIR: dir }, encoding: 'utf8' });
  assert.equal(out.trim(), 'ephemere');
});

test('les cles etrangeres sont appliquees', () => {
  const out = run(`
    try { await db.p.run("INSERT INTO project_members (project_id, user_id, role_on_project) VALUES (999, 1, 'x')"); console.log('accepte'); }
    catch (e) { console.log(e.message); }
  `);
  assert.match(out, /FOREIGN KEY/i);
});
