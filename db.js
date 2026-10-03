const mysql = require('mysql2/promise');

// XAMPP : user=root, password='' (vide par défaut)
// Si tu as mis un mot de passe root, mets-le dans DB_PASS.
const config = {
  host:     process.env.DB_HOST || '127.0.0.1',
  port:     parseInt(process.env.DB_PORT || '3306', 10),
  user:     process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  waitForConnections: true,
  connectionLimit: 10,
  multipleStatements: false,
  charset: 'utf8mb4_unicode_ci',
  timezone: 'Z'
};

// Pool vulnérable (accès à shop_vulnerable)
const poolVuln = mysql.createPool({ ...config, database: 'shop_vulnerable' });

// Pool sécurisé (accès à shop_secure)
const poolSecure = mysql.createPool({ ...config, database: 'shop_secure' });

module.exports = { poolVuln, poolSecure };