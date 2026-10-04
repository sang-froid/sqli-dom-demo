// Configuration par environnement. Les valeurs viennent de process.env ; un fichier
// .env (a la racine du projet, voir .env.example) est lu au demarrage s'il existe, sans
// jamais ecraser une variable deja definie dans l'environnement du shell.

const fs = require('fs');
const path = require('path');

function loadDotEnv(file) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch { return; }
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/i);
    if (!m || line.trim().startsWith('#')) continue;
    const value = m[2].replace(/^(['"])(.*)\1$/, '$2');
    if (process.env[m[1]] === undefined) process.env[m[1]] = value;
  }
}

loadDotEnv(path.join(__dirname, '.env'));

const env = process.env;
const bool = (v, fallback) => (v === undefined || v === '' ? fallback : /^(1|true|yes|on)$/i.test(v));
const int = (v, fallback) => (Number.isFinite(Number(v)) && v !== undefined && v !== '' ? Number(v) : fallback);

const nodeEnv = env.NODE_ENV || 'development';
const isProd = nodeEnv === 'production';

module.exports = {
  nodeEnv,
  isProd,
  port: int(env.PORT, 3000),
  // ':memory:' pour une base jetable (tests, demo ephemere) ; sinon un fichier persistant.
  dbPath: env.DB_PATH === ':memory:' ? ':memory:' : path.resolve(__dirname, env.DB_PATH || 'data/atrium.db'),
  logDir: path.resolve(__dirname, env.LOG_DIR || 'logs'),
  sessionTtlHours: int(env.SESSION_TTL_HOURS, 8),
  cookieSecure: bool(env.COOKIE_SECURE, isProd),
  trustProxy: bool(env.TRUST_PROXY, false),
  // Affiche les comptes de demo (identifiants compris) sur l'ecran de connexion.
  // Pratique pour la soutenance, a ne jamais activer hors labo.
  demoAccounts: bool(env.DEMO_ACCOUNTS, !isProd),
  bcryptRounds: int(env.BCRYPT_ROUNDS, 10),
  loginMaxAttempts: int(env.LOGIN_MAX_ATTEMPTS, 5),
  loginWindowMinutes: int(env.LOGIN_WINDOW_MINUTES, 15),
};

if (isProd && module.exports.demoAccounts) {
  console.warn('[config] ATTENTION : DEMO_ACCOUNTS est actif en production.');
}
