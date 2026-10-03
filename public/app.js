// ── Navigation ───────────────────────────────
document.querySelectorAll('.menu button').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.panel').forEach(p =>
      p.classList.toggle('active', p.id === 'tab-' + btn.dataset.tab));
    document.querySelectorAll('.menu button').forEach(b =>
      b.classList.toggle('active', b === btn));
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
});

function setP(p) {
  document.getElementById('payload').value = p;
}
window.setP = setP;

// ── Exécution des deux versions ──────────────
async function runBoth() {
  const category = document.getElementById('payload').value;

  // Reset des encadrés de verdict
  document.getElementById('attackVerdict').style.display = 'none';

  const [vuln, safe] = await Promise.all([
    fetch(`/api/vulnerable?category=${encodeURIComponent(category)}`).then(r => r.json()),
    fetch(`/api/secure?category=${encodeURIComponent(category)}`).then(r => r.json())
  ]);

  renderColumn('Vuln', vuln, category);
  renderColumn('Safe', safe, category);
  renderAttackVerdict(vuln, safe, category);
}
window.runBoth = runBoth;

// ── Détection du type d'attaque ──────────────
function detectAttack(category) {
  if (/union\s+select.*users/i.test(category)) return 'passwords';
  if (/union\s+select/i.test(category))        return 'union';
  if (/sleep\s*\(/i.test(category))            return 'time';
  if (/extractvalue|updatexml/i.test(category)) return 'error';
  if (/and\s+\d+\s*=\s*\d+/i.test(category))   return 'boolean';
  if (/'/.test(category))                      return 'quote';
  return null;
}

// ── Affichage d'une colonne ──────────────────
function renderColumn(side, data, category) {
  // Requête SQL
  let sqlText = data.sql;
  if (data.params) {
    sqlText += '\n\n-- Paramètres liés\n-- ' + JSON.stringify(data.params);
  }
  document.getElementById('sql' + side).textContent = sqlText;

  // Analyse
  const analysisBox = document.getElementById('analysis' + side);
  analysisBox.innerHTML = '';
  (data.analysis || []).forEach(step => {
    const div = document.createElement('div');
    div.className = 'analysis-step ' + (step.type || '');
    const label = document.createElement('span');
    label.className = 'as-label';
    label.textContent = step.label;
    const value = document.createElement('div');
    value.className = 'as-value';
    value.textContent = step.value;
    div.appendChild(label);
    div.appendChild(value);
    analysisBox.appendChild(div);
  });

  // Résultat — on détecte l'attaque pour un affichage spécial
  const resultBox = document.getElementById('result' + side);
  resultBox.innerHTML = '';

  const attack = detectAttack(category);

  if (data.error) {
    const p = document.createElement('p');
    p.className = 'error-msg';
    p.textContent = '❌ ' + data.error;
    resultBox.appendChild(p);
    return;
  }

  if (!data.rows || !data.rows.length) {
    const p = document.createElement('p');
    p.className = 'muted';
    p.textContent = 'Aucune ligne retournée.';
    resultBox.appendChild(p);

    // Si c'était une attaque et qu'on est côté sécurisé → confirmer le blocage
    if (attack && side === 'Safe') {
      const banner = document.createElement('div');
      banner.className = 'attack-banner blocked';
      banner.innerHTML = `
        <div class="ab-icon">🛡</div>
        <div class="ab-content">
          <div class="ab-title">ATTAQUE BLOQUÉE</div>
          <div class="ab-sub">Le payload a été traité comme une simple chaîne de caractères. Aucune donnée exfiltrée.</div>
        </div>
      `;
      resultBox.appendChild(banner);
    }
    return;
  }

  // ─── CAS ATTAQUE UNION RÉUSSIE côté vulnérable ───
  if (attack === 'passwords' && side === 'Vuln') {
    // On affiche un encadré spectaculaire avec les identifiants volés
    const banner = document.createElement('div');
    banner.className = 'attack-banner success';
    banner.innerHTML = `
      <div class="ab-icon">🚨</div>
      <div class="ab-content">
        <div class="ab-title">ATTAQUE RÉUSSIE — ${data.rows.length} COMPTE(S) COMPROMIS</div>
        <div class="ab-sub">Données extraites de la table <code>users</code> via UNION SELECT :</div>
      </div>
    `;
    resultBox.appendChild(banner);

    // Table spéciale des identifiants volés
    const stolenTable = document.createElement('table');
    stolenTable.className = 'stolen-table';
    stolenTable.innerHTML = `
      <thead>
        <tr>
          <th>Username</th>
          <th>Password</th>
          <th>Role</th>
        </tr>
      </thead>
    `;
    const tbody = document.createElement('tbody');
    data.rows.forEach(row => {
      const tr = document.createElement('tr');
      // Les valeurs sont : id, username, password, role (colonnes renommées
      // en id/name/price/category par MySQL car c'est la 1ère requête)
      const values = Object.values(row);
      tr.innerHTML = `
        <td class="stolen-user">${escapeHtml(values[1] ?? '')}</td>
        <td class="stolen-pass">${escapeHtml(values[2] ?? '')}</td>
        <td class="stolen-role">${escapeHtml(values[3] ?? '')}</td>
      `;
      tbody.appendChild(tr);
    });
    stolenTable.appendChild(tbody);
    resultBox.appendChild(stolenTable);

    // Message pédagogique
    const explain = document.createElement('p');
    explain.className = 'stolen-explain';
    explain.innerHTML = `💡 <strong>Ce qui vient de se passer :</strong> grâce au fragment <code>UNION SELECT id,username,password,role FROM users</code>, MySQL a exécuté <em>deux</em> requêtes au lieu d'une. Le serveur a renvoyé les colonnes de la <em>première</em> requête (<code>id, name, price, category</code>) mais remplies avec les <em>valeurs</em> de la seconde (utilisateurs, mots de passe, rôles).`;
    resultBox.appendChild(explain);
    return;
  }

  // ─── CAS GÉNÉRIQUE ───
  const table = document.createElement('table');
  const head = table.insertRow();
  Object.keys(data.rows[0]).forEach(k => {
    const th = document.createElement('th');
    th.textContent = k;
    head.appendChild(th);
  });
  data.rows.forEach(row => {
    const tr = table.insertRow();
    Object.values(row).forEach(v => {
      const td = tr.insertCell();
      td.textContent = v;
      if (/SUPER_SECRET|monmotdepasse|toor|admin|secret/i.test(String(v))) {
        td.classList.add('sensitive');
      }
    });
  });
  resultBox.appendChild(table);
}

// ── Verdict global sous les 2 colonnes ───────
function renderAttackVerdict(vuln, safe, category) {
  const attack = detectAttack(category);
  if (!attack) return;

  const box = document.getElementById('attackVerdict');
  const content = document.getElementById('attackVerdictContent');

  const vulnCount = vuln.rows?.length || 0;
  const safeCount = safe.rows?.length || 0;

  content.innerHTML = `
    <div class="av-grid">
      <div class="av-item bad">
        <div class="av-label">Version vulnérable</div>
        <div class="av-value">${vulnCount}</div>
        <div class="av-sub">ligne(s) exfiltrée(s)</div>
      </div>
      <div class="av-item good">
        <div class="av-label">Version sécurisée</div>
        <div class="av-value">${safeCount}</div>
        <div class="av-sub">ligne(s) exfiltrée(s)</div>
      </div>
    </div>
    <p class="av-text">
      <strong>Même entrée, deux comportements opposés.</strong>
      Le code vulnérable a concaténé le payload dans la requête → MySQL l'a interprété comme du SQL.
      Le code sécurisé a utilisé un <code>?</code> → MySQL l'a traité comme une donnée inerte.
    </p>
  `;
  box.style.display = 'block';
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}