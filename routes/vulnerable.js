const express = require('express');
const { poolVuln } = require('../db');

module.exports = () => {
  const router = express.Router();

  router.get('/search', async (req, res) => {
    const t0 = process.hrtime.bigint();
    const category = req.query.category ?? '';

    // ❌ CWE-89 : concaténation directe
    const sql = `SELECT id, name, price, category FROM products WHERE category = '${category}'`;

    req.log?.({ route: 'vulnerable', sql, category });

    try {
      const [rows] = await poolVuln.query(sql);   // query() ≠ execute()
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;

      res.json({
        sql,
        rows,
        meta: {
          technique:  classify(category),
          rowCount:   rows.length,
          execTimeMs: +ms.toFixed(2),
          columns:    rows.length ? Object.keys(rows[0]) : []
        }
      });
    } catch (e) {
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      res.status(400).json({
        sql,
        error: {
          code:     e.code,
          errno:    e.errno,
          sqlState: e.sqlState,
          message:  e.sqlMessage || e.message
        },
        meta: { execTimeMs: +ms.toFixed(2) },
        finding: "CWE-209 — fuite d'information via message d'erreur SQL brut"
      });
    }
  });

  function classify(input) {
    if (/union\s+(all\s+)?select/i.test(input))       return 'UNION-based';
    if (/sleep\s*\(/i.test(input))                    return 'Time-based blind';
    if (/benchmark\s*\(/i.test(input))                return 'Time-based (benchmark)';
    if (/and\s+\d+\s*=\s*\d+/i.test(input))           return 'Boolean-based blind';
    if (/extractvalue|updatexml|floor/i.test(input))  return 'Error-based';
    if (/'/.test(input))                              return 'Quote probing';
    return 'Legitimate query';
  }

  return router;
};