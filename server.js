// Point d'entree : attend que la base soit prete, puis ecoute sur PORT.
// Voir app.js pour l'assemblage et routes/lab.js pour les cinq surfaces vulnerables.

const config = require('./config');
const db = require('./db');
const { purgeExpiredSessions } = require('./middleware/session');
const app = require('./app');

db.ready
  .then(() => {
    const server = app.listen(config.port, () => {
      console.log(`Atrium (labo DOM-SQLi) disponible sur http://localhost:${config.port}`);
      console.log(`Base : ${config.dbPath} · environnement : ${config.nodeEnv}`);
    });

    purgeExpiredSessions().catch(() => {});
    const timer = setInterval(() => purgeExpiredSessions().catch(() => {}), 3600 * 1000);
    timer.unref();

    const shutdown = () => {
      server.close(() => db.close(() => process.exit(0)));
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  })
  .catch((err) => {
    console.error('Initialisation de la base impossible :', err);
    process.exit(1);
  });
