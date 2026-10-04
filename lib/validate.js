// Validation des entrees des routes d'ecriture. Chaque helper leve une HttpError(400)
// avec un message lisible ; les valeurs retournees sont nettoyees (trim, types).

const { HttpError } = require('./http');

const bad = (msg) => new HttpError(400, msg);

function string(body, field, label, { min = 1, max = 200, optional = false } = {}) {
  const raw = body[field];
  if (raw === undefined || raw === null || raw === '') {
    if (optional) return null;
    throw bad(`${label} est obligatoire.`);
  }
  if (typeof raw !== 'string') throw bad(`${label} est invalide.`);
  const v = raw.trim();
  if (v.length < min) throw bad(`${label} est trop court (${min} caracteres minimum).`);
  if (v.length > max) throw bad(`${label} est trop long (${max} caracteres maximum).`);
  return v;
}

function int(body, field, label, { min = 0, max = Number.MAX_SAFE_INTEGER, optional = false } = {}) {
  const raw = body[field];
  if (raw === undefined || raw === null || raw === '') {
    if (optional) return null;
    throw bad(`${label} est obligatoire.`);
  }
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) throw bad(`${label} est invalide.`);
  return n;
}

function oneOf(body, field, label, values) {
  const v = body[field];
  if (!values.includes(v)) throw bad(`${label} doit etre parmi : ${values.join(', ')}.`);
  return v;
}

function bool(body, field, fallback = false) {
  const v = body[field];
  if (v === undefined) return fallback;
  if (typeof v !== 'boolean') throw bad(`Le champ "${field}" doit etre un booleen.`);
  return v;
}

function email(body, field = 'email', { optional = false } = {}) {
  const v = string(body, field, 'L\'e-mail', { max: 120, optional });
  if (v === null) return null;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) throw bad('L\'e-mail est invalide.');
  return v;
}

function username(body, field = 'username') {
  const v = string(body, field, 'Le nom d\'utilisateur', { min: 3, max: 32 });
  if (!/^[a-z0-9._-]+$/i.test(v)) {
    throw bad('Le nom d\'utilisateur ne peut contenir que lettres, chiffres, point, tiret et underscore.');
  }
  return v;
}

function date(body, field, label, { optional = true } = {}) {
  const v = string(body, field, label, { max: 10, optional });
  if (v === null) return null;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(v) || Number.isNaN(Date.parse(v))) throw bad(`${label} doit etre au format AAAA-MM-JJ.`);
  return v;
}

// Politique de mot de passe : 10 caracteres minimum, au moins une lettre et un chiffre.
function password(value, label = 'Le mot de passe') {
  if (typeof value !== 'string') throw bad(`${label} est obligatoire.`);
  if (value.length < 10) throw bad(`${label} doit faire au moins 10 caracteres.`);
  if (value.length > 128) throw bad(`${label} est trop long.`);
  if (!/[A-Za-z]/.test(value) || !/\d/.test(value)) throw bad(`${label} doit contenir au moins une lettre et un chiffre.`);
  return value;
}

function idParam(req, name = 'id') {
  const n = Number(req.params[name]);
  if (!Number.isInteger(n) || n < 1) throw new HttpError(404, 'Ressource introuvable.');
  return n;
}

module.exports = { string, int, oneOf, bool, email, username, date, password, idParam };
