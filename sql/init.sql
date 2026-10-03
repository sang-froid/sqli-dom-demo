-- ═══════════════════════════════════════════════════════════════════
--  SQLi DOM — Base MySQL vulnérable + base sécurisée (miroir)
--  Cible : XAMPP MySQL 8.0 / MariaDB 10.4+
--  Usage  : mysql -u root < sql/init.sql
-- ═══════════════════════════════════════════════════════════════════

DROP DATABASE IF EXISTS shop_vulnerable;
DROP DATABASE IF EXISTS shop_secure;

-- ═══════════════ BASE VULNÉRABLE ═══════════════
CREATE DATABASE shop_vulnerable CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE shop_vulnerable;

CREATE TABLE users (
  id            INT PRIMARY KEY AUTO_INCREMENT,
  username      VARCHAR(64) UNIQUE NOT NULL,
  email         VARCHAR(128),
  password_hash VARCHAR(255) NOT NULL,
  role          ENUM('user','admin','superadmin') DEFAULT 'user',
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE products (
  id       INT PRIMARY KEY AUTO_INCREMENT,
  name     VARCHAR(128),
  price    DECIMAL(10,2),
  category VARCHAR(64),
  stock    INT DEFAULT 0
) ENGINE=InnoDB;

CREATE TABLE secrets (
  id             INT PRIMARY KEY AUTO_INCREMENT,
  label          VARCHAR(64),
  value          TEXT,
  classification ENUM('internal','confidential','secret') DEFAULT 'internal'
) ENGINE=InnoDB;

CREATE TABLE audit_log (
  id       INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(64),
  action   VARCHAR(255),
  ip       VARCHAR(45),
  ts       DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ── Utilisateurs (hashs bcrypt coût 12, pré-calculés) ──
INSERT INTO users (username, email, password_hash, role) VALUES
('admin',      'admin@corp.local',  '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYqVr/ifK6u', 'superadmin'),
('j.martin',   'jmartin@corp.local','$2b$12$8K9sX2pQwErTyUiOpAsDfGhJkLzXcVbNmQwErTyUiOpAsDfGhJkL', 'admin'),
('a.dubois',   'adubois@corp.local','$2b$12$3FgHjKlZxCvBnMqWeRtYuIoPaSdFgHjKlZxCvBnMqWeRtYuIoPaSd', 'user'),
('s.leroy',    'sleroy@corp.local', '$2b$12$9ZxCvBnMqWeRtYuIoPaSdFgHjKlZxCvBnMqWeRtYuIoPaSdFgHjK', 'user'),
('svc_backup', 'backup@corp.local', '$2b$12$5TyUiOpAsDfGhJkLzXcVbNmQwErTyUiOpAsDfGhJkLzXcVbNmQwE', 'admin');

-- ── Produits ──
INSERT INTO products (name, price, category, stock) VALUES
('Clavier mecanique RGB',   89.90, 'informatique', 42),
('Souris sans fil',         39.90, 'informatique', 120),
('Ecran 27 pouces 4K',     349.00, 'informatique', 15),
('Cahier 200 pages',         2.50, 'papeterie',    500),
('Stylo bille bleu',         0.80, 'papeterie',   1200),
('Classeur A4',             12.00, 'papeterie',     80),
('Chaise ergonomique',     249.00, 'mobilier',       8),
('Bureau ajustable',       599.00, 'mobilier',       3);

-- ── Secrets crown-jewel ──
INSERT INTO secrets (label, value, classification) VALUES
('stripe_live_key',       'STRIPE_SECRET_KEY_EXAMPLE',       'secret'),
('aws_access_key_id',     'AWS_ACCESS_KEY_ID_EXAMPLE',        'secret'),
('aws_secret_access_key', 'AWS_SECRET_ACCESS_KEY_EXAMPLE',    'secret'),
('jwt_signing_key',       'JWT_SIGNING_KEY_EXAMPLE',          'secret'),
('internal_api_token',    'INTERNAL_API_TOKEN_EXAMPLE',       'confidential'),
('db_replica_password',   'DB_REPLICA_PASSWORD_EXAMPLE',      'confidential');
-- ═══════════════ BASE SÉCURISÉE (miroir) ═══════════════
CREATE DATABASE shop_secure CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE shop_secure;

CREATE TABLE products (
  id       INT PRIMARY KEY AUTO_INCREMENT,
  name     VARCHAR(128),
  price    DECIMAL(10,2),
  category VARCHAR(64),
  stock    INT DEFAULT 0
) ENGINE=InnoDB;

INSERT INTO products (name, price, category, stock)
SELECT name, price, category, stock FROM shop_vulnerable.products;

-- ⚠️ PAS de table `users` ni `secrets` dans shop_secure :
--    illustration du principe du moindre privilège côté schéma.

-- ═══════════════ UTILISATEUR APPLICATIF (moindre privilège) ═══════════════
-- Décommenter pour la démonstration "compte DB restreint"
-- CREATE USER 'app_svc'@'localhost' IDENTIFIED BY 'AppSvc!2026';
-- GRANT SELECT ON shop_secure.products TO 'app_svc'@'localhost';
-- FLUSH PRIVILEGES;