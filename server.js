const express = require('express');
const mysql = require('mysql2/promise');
const path = require('path');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));

const db = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'shop'
});

// ═══════════════════════════════════════════════════════
//  ROUTE VULNÉRABLE
// ═══════════════════════════════════════════════════════
app.get('/api/vulnerable', async (req, res) => {
  const category = req.query.category || '';

  // ❌ Concaténation directe : l'entrée utilisateur devient du CODE SQL
  const sql = "SELECT id, name, price, category FROM products WHERE category = '" + category + "'";

  try {
    const [rows] = await db.query(sql);
    res.json({
      mode: 'vulnerable',
      sql,
      rows,
      analysis: analyzeVulnerable(category, sql)
    });
  } catch (e) {
    res.json({
      mode: 'vulnerable',
      sql,
      error: e.message,
      analysis: analyzeVulnerable(category, sql)
    });
  }
});

// ═══════════════════════════════════════════════════════
//  ROUTE SÉCURISÉE
// ═══════════════════════════════════════════════════════
app.get('/api/secure', async (req, res) => {
  const category = req.query.category || '';

  // ✅ Requête préparée : le "?" est une DONNÉE, jamais du code
  const sql = 'SELECT id, name, price, category FROM products WHERE category = ?';

  try {
    const [rows] = await db.execute(sql, [category]);
    res.json({
      mode: 'secure',
      sql,
      params: [category],
      rows,
      analysis: analyzeSecure(category)
    });
  } catch (e) {
    res.json({
      mode: 'secure',
      sql,
      params: [category],
      error: e.message,
      analysis: analyzeSecure(category)
    });
  }
});

// ═══════════════════════════════════════════════════════
//  ANALYSE : explique ce que fait le payload
// ═══════════════════════════════════════════════════════
function analyzeVulnerable(input, finalSql) {
  const steps = [];
  steps.push({
    label: 'Entrée utilisateur',
    value: input || '(vide)'
  });
  steps.push({
    label: 'Requête construite',
    value: finalSql
  });

  if (/union\s+select/i.test(input)) {
    steps.push({
      type: 'danger',
      label: '🚨 INJECTION UNION DÉTECTÉE',
      value: "Le fragment ' UNION SELECT ... a été CONCATÉNÉ dans la requête. " +
             "MySQL l'interprète comme du SQL légitime et exécute les DEUX requêtes. " +
             "L'attaquant peut lire n'importe quelle table."
    });
  } else if (/'/.test(input)) {
    steps.push({
      type: 'warning',
      label: '⚠ Guillemet détecté',
      value: "Le guillemet ferme la chaîne 'informatique' et casse la syntaxe SQL. " +
             "C'est le point d'entrée pour toute injection."
    });
  } else {
    steps.push({
      type: 'ok',
      label: '✓ Requête normale',
      value: "Aucun caractère suspect. La requête s'exécute comme prévu."
    });
  }

  return steps;
}

function analyzeSecure(input) {
  const steps = [];
  steps.push({
    label: 'Entrée utilisateur',
    value: input || '(vide)'
  });
  steps.push({
    label: 'Requête préparée',
    value: 'SELECT id, name, price, category FROM products WHERE category = ?'
  });
  steps.push({
    label: 'Paramètre lié',
    value: JSON.stringify([input])
  });

  if (/union|select|'|--/i.test(input)) {
    steps.push({
      type: 'safe',
      label: '🛡 Payload neutralisé',
      value: "Le '?' est remplacé par MySQL APRÈS analyse de la requête. " +
             "Le payload devient une simple CHAÎNE DE CARACTÈRES. " +
             "MySQL cherche une catégorie qui s'appelle littéralement \"" +
             input + "\" → aucun résultat."
    });
  } else {
    steps.push({
      type: 'ok',
      label: '✓ Requête normale',
      value: "Entrée légitime. Le '?' est remplacé par la vraie valeur et MySQL cherche normalement."
    });
  }

  return steps;
}

app.listen(3001, () => console.log(' http://localhost:3001'));