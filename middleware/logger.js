const fs = require('fs');
const path = require('path');

const LOG_DIR = path.join(__dirname, '..', 'logs');
fs.mkdirSync(LOG_DIR, { recursive: true });

const stream = fs.createWriteStream(
  path.join(LOG_DIR, 'requests.jsonl'),
  { flags: 'a' }
);

module.exports = (req, res, next) => {
  req.log = (payload) => {
    const entry = {
      ts: new Date().toISOString(),
      ip: req.ip,
      method: req.method,
      url: req.originalUrl,
      ua: req.get('user-agent'),
      ...payload
    };
    stream.write(JSON.stringify(entry) + '\n');
  };
  next();
};