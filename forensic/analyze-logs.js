const fs = require('fs');
const path = require('path');
const readline = require('readline');

const LOG = path.join(__dirname, '..', 'logs', 'requests.jsonl');
const PATTERNS = {
  union:      /union\s+(all\s+)?select/i,
  boolean:    /and\s+\d+\s*=\s*\d+/i,
  timeBased:  /sleep\s*\(\s*\d+\s*\)/i,
  errorBased: /extractvalue|updatexml/i,
  comment:    /--\s|\/\*|\#/,
  quote:      /'/
};

(async () => {
  if (!fs.existsSync(LOG)) {
    console.log('Pas de log — lance d\'abord un exploit.');
    return;
  }
  const stats = { total: 0, suspicious: 0, byTechnique: {}, byIp: {} };
  const rl = readline.createInterface({ input: fs.createReadStream(LOG) });

  for await (const line of rl) {
    try {
      const e = JSON.parse(line);
      stats.total++;
      const hits = [];
      for (const [k, re] of Object.entries(PATTERNS)) {
        if (re.test(e.sql || '')) hits.push(k);
      }
      if (hits.length) {
        stats.suspicious++;
        stats.byIp[e.ip] = (stats.byIp[e.ip] || 0) + 1;
        hits.forEach(h => stats.byTechnique[h] = (stats.byTechnique[h] || 0) + 1);
      }
    } catch {}
  }

  console.log('\n═══ Analyse forensique ═══');
  console.log(`Requêtes totales   : ${stats.total}`);
  console.log(`Requêtes suspectes : ${stats.suspicious} (${(stats.suspicious/stats.total*100).toFixed(1)}%)`);
  console.log('\nPar technique :');
  console.table(stats.byTechnique);
  console.log('\nTop IPs :');
  console.table(stats.byIp);
})();