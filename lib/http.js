// Utilitaires HTTP partages : erreur typee, enveloppe async pour Express 4, gestionnaire
// d'erreurs JSON.

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  if (res.headersSent) return next(err);
  let e = err;
  if (err.type === 'entity.parse.failed') e = new HttpError(400, 'Corps JSON invalide.');
  if (err.type === 'entity.too.large') e = new HttpError(413, 'Requete trop volumineuse.');
  const status = e.status || 500;
  if (status >= 500) console.error(err);
  res.status(status).json({ error: status >= 500 ? 'Erreur interne.' : e.message });
}

module.exports = { HttpError, wrap, errorHandler };
