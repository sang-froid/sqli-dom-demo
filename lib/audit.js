// Journal d'audit des actions d'ecriture (table audit_log), consultable par les admins.
// Ne jamais y mettre de secret : mot de passe, jeton de session, etc.

const db = require('../db');

async function audit(actorId, action, targetType = null, targetId = null, detail = null) {
  const text = detail === null || detail === undefined
    ? null
    : (typeof detail === 'string' ? detail : JSON.stringify(detail));
  try {
    await db.p.run(
      'INSERT INTO audit_log (ts, actor_id, action, target_type, target_id, detail) VALUES (?, ?, ?, ?, ?, ?)',
      [new Date().toISOString(), actorId, action, targetType, targetId, text]
    );
  } catch (err) {
    console.error('[audit] ecriture impossible :', err.message);
  }
}

module.exports = { audit };
