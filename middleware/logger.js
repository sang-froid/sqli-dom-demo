// Journalisation des requetes SQL executees par l'API, pour la partie "detection"
// du rapport. Chaque appel a req.sqlLog(...) ecrit une ligne JSON dans
// <LOG_DIR>/requests.jsonl (par defaut logs/), que forensic/analyze-logs.js relit ensuite
// pour reperer les motifs suspects.

const fs = require('fs');
const path = require('path');
const config = require('../config');

fs.mkdirSync(config.logDir, { recursive: true });

const stream = fs.createWriteStream(
  path.join(config.logDir, 'requests.jsonl'),
  { flags: 'a' }
);

module.exports = (req, res, next) => {
  req.sqlLog = (payload) => {
    const entry = {
      ts: new Date().toISOString(),
      ip: req.ip,
      method: req.method,
      url: req.originalUrl,
      ...payload,
    };
    stream.write(JSON.stringify(entry) + '\n');
  };
  next();
};
