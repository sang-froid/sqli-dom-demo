// Relit logs/requests.jsonl et detecte les motifs d'injection SQL connus
// dans les requetes effectivement executees. A lancer apres avoir manipule
// le labo en mode Vulnerable : `npm run forensic`.

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const LOG = path.join(__dirname, '..', 'logs', 'requests.jsonl');

const PATTERNS = {
  booleanOr: /\bor\b\s*\d+\s*=\s*\d+/i,
  booleanAnd: /\band\b\s*\d+\s*=\s*\d+/i,
  union: /union\s+(all\s+)?select/i,
  comment: /--\s|\/\*|#/,
  stacked: /;\s*(update|delete|insert|drop)\b/i,
};

(async () => {
  if (!fs.existsSync(LOG)) {
    console.log('Aucun log trouvé. Utilisez le labo (mode Vulnérable) puis relancez cette analyse.');
    return;
  }

  const stats = { total: 0, suspicious: 0, byTechnique: {} };
  const rl = readline.createInterface({ input: fs.createReadStream(LOG) });

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry;
    try { entry = JSON.parse(line); } catch { continue; }

    stats.total++;
    const sql = entry.sql || '';
    const hits = Object.entries(PATTERNS)
      .filter(([, re]) => re.test(sql))
      .map(([name]) => name);

    if (hits.length) {
      stats.suspicious++;
      hits.forEach(h => { stats.byTechnique[h] = (stats.byTechnique[h] || 0) + 1; });
      console.log(`⚠  [${entry.ts}] ${entry.mode} — ${hits.join(', ')}`);
      console.log(`   SQL : ${sql}`);
    }
  }

  console.log('\n═══ Analyse forensique ═══');
  console.log(`Requêtes journalisées : ${stats.total}`);
  console.log(`Requêtes suspectes    : ${stats.suspicious}`);
  console.log('Par technique détectée :', stats.byTechnique);
})();
