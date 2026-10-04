// Supprime le fichier de base de donnees (et ses fichiers annexes SQLite) : au prochain
// demarrage, le schema est recree et les donnees de demonstration reinserees.
// A utiliser avant une soutenance pour repartir d'un etat propre. Arretez le serveur avant.

const fs = require('fs');
const config = require('../config');

if (config.dbPath === ':memory:') {
  console.log('DB_PATH=:memory: -- rien a supprimer (la base est jetable).');
  process.exit(0);
}

let removed = 0;
for (const suffix of ['', '-wal', '-shm', '-journal']) {
  try { fs.unlinkSync(config.dbPath + suffix); removed++; } catch { /* absent */ }
}
console.log(removed ? `Base supprimee : ${config.dbPath}` : `Aucune base a supprimer (${config.dbPath}).`);
