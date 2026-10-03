const express = require('express');
const { poolSecure } = require('../db');

module.exports = () => {
  const router = express.Router();

  const ALLOWED = /^[\p{L}0-9 _-]{1,30}$/u;
  const SQL = 'SELECT id, name, price, category FROM products WHERE category = ?';

  router.get('/search', async (req, res) => {
    const category = String(req.query.category ?? '');

    if (!ALLOWED.test(category)) {
      req.log?.({ route: 'secure', rejected: true, category });
      return res.status(400).json({
        error: 'Entrée rejetée — caractères non autorisés',
        layers: ['whitelist']
      });
    }

    const [rows] = await poolSecure.execute(SQL, [category]);
    res.json({
      sql: SQL,
      params: [category],
      rows,
      meta: { rowCount: rows.length, layers: ['whitelist', 'prepared-statement', 'least-privilege-db'] }
    });
  });

  return router;
};