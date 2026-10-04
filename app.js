// Assemblage de l'application Express (sans ecouter de port : voir server.js, et
// tests/ qui demarrent l'app sur un port aleatoire).
//
// Atrium : annuaire interne + projets/documents, avec un vrai modele d'autorisation.
// Cinq surfaces volontairement vulnerables a l'injection SQL (routes/lab.js :
// /api/profile, /api/search, /api/lab/directory, /api/lab/project et
// /api/lab/login-history, en mode "vulnerable") ; tout le reste de l'application est
// ecrit proprement (requetes parametrees, sessions, droits verifies cote serveur).
// A lancer uniquement en local.

const express = require('express');
const path = require('path');
const config = require('./config');
const sqlLogger = require('./middleware/logger');
const { securityHeaders, apiNoStore, csrfGuard } = require('./middleware/security');
const { loadSession } = require('./middleware/session');
const { HttpError, wrap, errorHandler } = require('./lib/http');

const app = express();
app.disable('x-powered-by');
if (config.trustProxy) app.set('trust proxy', 1);

app.use(securityHeaders);
app.use(sqlLogger);

const api = express.Router();
api.use(apiNoStore);
api.use(express.json({ limit: '100kb' }));
api.use(csrfGuard);
api.use(wrap(loadSession));
api.use(require('./routes/auth'));
api.use(require('./routes/directory'));
api.use(require('./routes/lab'));
api.use('/admin', require('./routes/admin'));
api.use(require('./routes/projects'));
api.use((req, res, next) => next(new HttpError(404, 'Route inconnue.')));
app.use('/api', api);

app.use(express.static(path.join(__dirname, 'public')));
app.use(errorHandler);

module.exports = app;
