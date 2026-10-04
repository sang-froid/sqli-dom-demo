// Aide pour les tests : demarre l'application complete sur un port aleatoire avec une
// base en memoire fraiche (chaque fichier de test tourne dans son propre processus, donc
// sa propre base), et fournit un client HTTP minimal qui conserve le cookie de session.

const os = require('os');
const path = require('path');

process.env.DB_PATH = ':memory:';
process.env.LOG_DIR = path.join(os.tmpdir(), `atrium-test-logs-${process.pid}`);
process.env.BCRYPT_ROUNDS = '4'; // hachage rapide : seul le comportement compte ici
process.env.DEMO_ACCOUNTS = 'true';
process.env.LOGIN_MAX_ATTEMPTS = '5';
process.env.NODE_ENV = 'test';

const db = require('../db');
const app = require('../app');

const ACCOUNTS = {
  alice: ['alice.martin', 'Password123'],        // collaboratrice, manager = Julien
  bassirou: ['bassirou.koffi', 'Password123'],    // RH, hors perimetre d'Alice
  nadia: ['nadia.benali', 'Password123'],        // Finance
  julien: ['julien.picard', 'Password123'],     // manager d'Alice, proprietaire du projet 1
  fatou: ['fatou.diarra', 'Password123'],        // Commercial
  admin: ['admin', 'Password123'],
};

class Client {
  constructor(base) {
    this.base = base;
    this.cookie = '';
  }

  async request(method, url, body, headers = {}) {
    const h = { 'X-Requested-With': 'atrium', ...headers };
    if (this.cookie) h.Cookie = this.cookie;
    if (body !== undefined) h['Content-Type'] = 'application/json';
    const res = await fetch(this.base + url, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) this.cookie = setCookie.split(';')[0].endsWith('=') ? '' : setCookie.split(';')[0];
    let data = null;
    try { data = await res.json(); } catch { /* corps vide */ }
    return { status: res.status, data, headers: res.headers };
  }

  get(url) { return this.request('GET', url); }
  post(url, body = {}) { return this.request('POST', url, body); }
  patch(url, body = {}) { return this.request('PATCH', url, body); }
  delete(url) { return this.request('DELETE', url); }

  async login(username, password) {
    return this.post('/api/auth/login', { username, password });
  }
}

async function start() {
  await db.ready;
  const server = await new Promise((resolve) => { const s = app.listen(0, () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;

  return {
    base,
    anonymous: () => new Client(base),
    async as(name) {
      const [u, p] = ACCOUNTS[name];
      const c = new Client(base);
      const r = await c.login(u, p);
      if (r.status !== 200) throw new Error(`connexion de ${name} impossible : ${r.status} ${JSON.stringify(r.data)}`);
      return c;
    },
    async close() {
      await new Promise((resolve) => server.close(resolve));
      await new Promise((resolve) => db.close(resolve));
    },
  };
}

module.exports = { start, ACCOUNTS, db };
