// Durcissement HTTP general (hors surfaces volontairement vulnerables du labo) :
// en-tetes de securite, et garde anti-CSRF sur les ecritures de l'API.
// Pas de Content-Security-Policy : les pages utilisent des scripts inline.

const { HttpError } = require('../lib/http');

function securityHeaders(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
}

// Les reponses de l'API contiennent des donnees personnelles : jamais mises en cache.
function apiNoStore(req, res, next) {
  res.setHeader('Cache-Control', 'no-store');
  next();
}

// Toute requete qui modifie l'etat doit porter l'en-tete X-Requested-With, qu'un
// formulaire HTML ou une requete cross-site simple ne peut pas poser. Associe a
// SameSite=Lax sur le cookie de session et a l'absence d'en-tetes CORS, ca ferme le CSRF.
function csrfGuard(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (req.get('X-Requested-With') !== 'atrium') {
    return next(new HttpError(403, 'Requete refusee (en-tete anti-CSRF manquant).'));
  }
  next();
}

module.exports = { securityHeaders, apiNoStore, csrfGuard };
