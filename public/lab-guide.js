// Cadres pedagogiques affiches en haut de chaque page : ils expliquent ce que fait la page,
// montrent la faille (cadre rouge, mode vulnerable) ou le correctif (cadre vert, mode
// corrige), le vrai code concerne, et permettent de LANCER l'attaque d'un clic pour voir le
// verdict sur la vraie application. Le mode suit la bascule "Mode demo" de la barre du haut.
//
// Tout le texte est ecrit ici, en dur (jamais issu de la base) ; il passe quand meme par
// esc() avant d'etre injecte. Les `...` d'un texte deviennent des <code>.

const LabGuide = (() => {
  const { esc } = AtriumShell;
  const inline = (s) => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>');
  const list = (items, tag = 'ul') => `<${tag}>${items.map((i) => `<li>${inline(i)}</li>`).join('')}</${tag}>`;

  // Une ligne de code : [type, texte], type = bad | good | ctx
  const code = (lines) => `<pre class="lg-code">${lines.map(([t, s]) =>
    `<span class="l ${t}">${t === 'good' ? '+ ' : t === 'bad' ? '- ' : '  '}${esc(s)}</span>`).join('')}</pre>`;
  const plain = (lines) => `<pre class="lg-code">${lines.map(([t, s]) =>
    `<span class="l ${t === 'good' ? 'ctx' : t}">${esc(s)}</span>`).join('')}</pre>`;

  // Verdict commun : lignes hors du perimetre de l'utilisateur (ni lui, ni ses subordonnes).
  const msg = (d, fallback) => String(d.error || fallback).replace(/\.+$/, '');
  const outOfScope = (rows, u) => (u.is_admin ? [] : (rows || []).filter((r) => r.id !== u.id && r.manager_id !== u.id));

  // ===================================================================== CONTENU
  const PAGES = {
    // ------------------------------------------------------------ fiche collaborateur
    profile: {
      title: 'Fiche collaborateur',
      about: {
        p: 'Cette page affiche la fiche complète d\'un collaborateur : identité, coordonnées, manager, bio, projets avec leurs documents (les confidentiels sont masqués hors de votre périmètre) et, pour la démo, le hash de son mot de passe.',
        items: [
          'Vous ne pouvez voir que **votre fiche et celles de vos subordonnés directs** (l\'administrateur voit tout).',
          'L\'identifiant vient de l\'adresse : `profile.html#id=2`. La page le transmet tel quel à `/api/profile?id=…`.',
        ],
      },
      vuln: {
        badge: 'FAILLE · Injection SQL (CWE-89)',
        headline: 'L\'identifiant de l\'URL est collé dans la requête SQL, à côté du filtre d\'autorisation',
        where: 'routes/lab.js · GET /api/profile · branche « vulnerable » (lignes ~109-115)',
        code: [
          ['bad', 'let sql = `SELECT … FROM users u … WHERE u.id = ${id}`;'],
          ['ctx', 'if (!isAdmin(sessionUser)) {'],
          ['bad', '  sql += ` AND (u.id = ${sessionUser.id} OR u.manager_id = ${sessionUser.id})`;'],
          ['ctx', '}'],
          ['ctx', 'db.all(sql, [], …);   // aucun paramètre : tout est du texte SQL'],
        ],
        why: [
          '`id` vient du navigateur et est inséré **tel quel** dans le texte de la requête : le serveur ne distingue plus la donnée (un numéro) du code SQL.',
          'Le contrôle d\'accès (« moi ou mes subordonnés ») est **dans la même chaîne** : un commentaire SQL `-- ` placé dans `id` coupe la requête juste avant et **annule le contrôle lui-même**.',
        ],
        steps: [
          'Connectez-vous avec un compte non-administrateur (ex. `alice.martin`) : le filtre est alors actif.',
          'Dans l\'adresse, remplacez l\'identifiant par `3 -- ` (c\'est Nadia, hors de votre périmètre) : `profile.html#id=3 -- `.',
          'Le serveur construit la requête ci-dessous : tout ce qui suit `--` est ignoré.',
        ],
        sql: [
          ['ctx', 'SELECT … FROM users u … WHERE u.id = 3 -- AND (u.id = 1 OR u.manager_id = 1)'],
          ['bad', '                                     ^^^^^^ tout ceci est maintenant un commentaire : le filtre a disparu'],
        ],
        outcome: 'Résultat : la fiche de Nadia s\'affiche **en entier, hash du mot de passe compris**, alors que vous n\'y avez pas droit. Avec `0 OR 1=1 -- ` on récupère **toutes** les fiches d\'un coup, et avec une simple apostrophe (`1\'`) la base répond par son message d\'erreur brut, qui révèle la structure de la requête.',
      },
      fix: {
        badge: 'CORRIGÉ · requête paramétrée + autorisation en code',
        headline: 'La valeur n\'est plus du SQL : c\'est un paramètre, et l\'accès est vérifié par le code',
        where: 'routes/lab.js · GET /api/profile · branche « secure » (lignes ~130-165)',
        diff: [
          ['bad', 'let sql = `… WHERE u.id = ${id}`;'],
          ['bad', 'sql += ` AND (u.id = ${sessionUser.id} OR u.manager_id = ${sessionUser.id})`;'],
          ['bad', 'db.all(sql, [], …);'],
          ['good', 'if (!/^\\d+$/.test(rawId)) return res.status(400).json({ error: \'un entier est attendu\' });'],
          ['good', 'const sql = `… WHERE u.id = ?`;                 // ? = emplacement de donnée'],
          ['good', 'db.all(sql, [Number(rawId)], …);               // la valeur voyage à part du SQL'],
          ['good', 'const allowed = isAdmin(u) || row.id === u.id || row.manager_id === u.id;'],
          ['good', 'if (!allowed) return res.status(403).json({ error: \'Accès refusé\' });'],
        ],
        why: [
          '**Validation** : seul un entier passe. `3 -- ` ou `1\'` sont refusés (HTTP 400) avant d\'atteindre la base.',
          '**Requête paramétrée** : même si une valeur piégée passait, `?` la traiterait comme une donnée, jamais comme du SQL.',
          '**Autorisation en code** : le droit de voir la fiche est vérifié **après** la requête, dans le programme — plus aucun commentaire SQL ne peut l\'annuler (HTTP 403 sinon).',
        ],
      },
      attacks: [
        {
          label: 'Lire la fiche de Nadia (hors périmètre)', id: '3 -- ',
          path: (m) => `/api/profile?id=${encodeURIComponent('3 -- ')}&mode=${m}`,
          verdict: (d, s, m, u) => {
            if (u.is_admin) return { kind: 'info', text: 'Vous êtes administrateur : vous voyez déjà tout. Reconnectez-vous avec alice.martin pour que le filtre soit actif.' };
            const rows = d.resultats || [];
            const out = outOfScope(rows, u);
            if (out.length) return { kind: 'bad', text: `ATTAQUE RÉUSSIE — fiche de ${out[0].full_name} (#${out[0].id}) lue alors qu'elle est hors de votre périmètre, hash du mot de passe inclus.` };
            return { kind: 'good', text: `ATTAQUE BLOQUÉE — HTTP ${s}: ${msg(d, 'aucune fiche hors périmètre renvoyée')}.` };
          },
        },
        {
          label: 'Aspirer toutes les fiches', id: '0 OR 1=1 -- ',
          path: (m) => `/api/profile?id=${encodeURIComponent('0 OR 1=1 -- ')}&mode=${m}`,
          verdict: (d, s, m, u) => {
            if (u.is_admin) return { kind: 'info', text: 'Vous êtes administrateur : le filtre n\'existe pas pour vous. Utilisez alice.martin.' };
            const out = outOfScope(d.resultats, u);
            if (out.length) return { kind: 'bad', text: `ATTAQUE RÉUSSIE — ${(d.resultats || []).length} fiches renvoyées, dont ${out.length} hors périmètre (avec leurs hash).` };
            return { kind: 'good', text: `ATTAQUE BLOQUÉE — HTTP ${s}: ${msg(d, 'aucune fiche renvoyée')}.` };
          },
        },
        {
          label: 'Faire parler la base (erreur SQL)', id: "1'",
          path: (m) => `/api/profile?id=${encodeURIComponent("1'")}&mode=${m}`,
          verdict: (d, s) => (d.error && /SQLITE|syntax|unrecognized|token/i.test(d.error)
            ? { kind: 'bad', text: `ATTAQUE RÉUSSIE — la base a répondu avec son message interne : « ${d.error} ». L'attaquant sait maintenant que son texte arrive dans la requête.` }
            : { kind: 'good', text: `ATTAQUE BLOQUÉE — HTTP ${s}: ${msg(d, 'aucune erreur interne divulguée')}.` }),
        },
      ],
    },

    // ------------------------------------------------------------ recherche avancee
    search: {
      title: 'Recherche avancée',
      about: {
        p: 'Cette page cherche des collaborateurs par nom, par service et par statut de projet. Elle croise trois tables (collaborateurs, membres de projet, projets) et n\'affiche que ce que votre périmètre autorise.',
        items: [
          'Chaque champ rempli ajoute **un filtre** à la requête (`AND … LIKE`, `AND department = …`, `AND status = …`).',
          'Une carte de résultat affiche cinq colonnes : id, nom, rôle, service, manager.',
        ],
      },
      vuln: {
        badge: 'FAILLE · Injection SQL de type UNION (CWE-89)',
        headline: 'Chaque filtre est concaténé : on peut greffer une 2ᵉ requête sur une AUTRE table',
        where: 'routes/lab.js · GET /api/search · branche « vulnerable » (lignes ~179-193)',
        code: [
          ['ctx', 'let sql = `SELECT id, full_name, role, department, manager_id FROM users u WHERE 1=1`;'],
          ['bad', 'if (q)          sql += ` AND u.full_name LIKE \'%${q}%\'`;'],
          ['bad', 'if (department) sql += ` AND u.department = \'${department}\'`;'],
          ['bad', 'if (status)     sql += ` AND … WHERE p.status = \'${status}\')`;'],
          ['ctx', 'if (!isAdmin(sessionUser)) sql += ` AND (u.id = … OR u.manager_id = …)`;'],
        ],
        why: [
          'Les valeurs sont entourées d\'apostrophes **dans le texte SQL**. Une seule apostrophe dans le champ « Nom » ferme le littéral et laisse l\'attaquant écrire du SQL.',
          '`UNION SELECT` ajoute les lignes d\'une **autre table** au résultat. Il faut juste respecter le même nombre de colonnes (5 ici) : les documents confidentiels s\'affichent alors comme s\'ils étaient des collaborateurs.',
          'Le `-- ` final met en commentaire la suite, donc aussi le filtre de périmètre.',
        ],
        steps: [
          'Dans le champ « Nom », saisissez (ou cliquez sur « Essayer » ci-dessous) :',
          '`zzz%\' UNION SELECT id, title, content, \'DOCUMENT\', NULL FROM documents WHERE confidential = 1 -- `',
          '`zzz%` ne correspond à personne ; le `\'` ferme le texte ; l\'`UNION` ajoute les documents.',
        ],
        sql: [
          ['ctx', "… WHERE 1=1 AND u.full_name LIKE '%zzz%'"],
          ['bad', "UNION SELECT id, title, content, 'DOCUMENT', NULL FROM documents WHERE confidential = 1"],
          ['bad', "-- %' AND (u.id = 1 OR u.manager_id = 1) ORDER BY u.full_name      <- commentaire"],
        ],
        outcome: 'Résultat : la liste affiche les **titres et le contenu des documents confidentiels** (service « DOCUMENT ») que vous n\'avez pas le droit de lire. En injectant `sqlite_master` ou `users.password` on pourrait de la même façon lister le schéma ou les hash.',
      },
      fix: {
        badge: 'CORRIGÉ · tous les filtres sont paramétrés',
        headline: 'Les valeurs saisies restent des données, quoi qu\'elles contiennent',
        where: 'routes/lab.js · GET /api/search · branche « secure » (lignes ~209-228)',
        diff: [
          ['bad', 'if (q) sql += ` AND u.full_name LIKE \'%${q}%\'`;'],
          ['bad', 'if (department) sql += ` AND u.department = \'${department}\'`;'],
          ['good', 'if (q) { sql += ` AND u.full_name LIKE ?`; params.push(`%${q}%`); }'],
          ['good', 'if (department) { sql += ` AND u.department = ?`; params.push(department); }'],
          ['good', 'if (status) { sql += ` … WHERE p.status = ?)`; params.push(status); }'],
          ['good', 'db.all(sql, params, …);'],
          ['good', 'const scoped = rows.filter(r => r.id === me.id || r.manager_id === me.id);'],
        ],
        why: [
          'Le texte SQL est **fixe** : il ne contient que des `?`. L\'UNION tapé dans « Nom » est cherché comme un simple nom (aucun résultat).',
          'Le périmètre est appliqué **en code** sur le résultat : même un filtre contourné ne ferait rien sortir du périmètre.',
          'Les erreurs ne sont plus renvoyées en clair (« Erreur interne ») : l\'attaquant n\'apprend plus rien de la requête.',
        ],
      },
      attacks: [
        {
          label: 'Exfiltrer les documents confidentiels (UNION)',
          q: "zzz%' UNION SELECT id, title, content, 'DOCUMENT', NULL FROM documents WHERE confidential = 1 -- ",
          path: (m) => `/api/search?mode=${m}&q=${encodeURIComponent("zzz%' UNION SELECT id, title, content, 'DOCUMENT', NULL FROM documents WHERE confidential = 1 -- ")}`,
          verdict: (d, s) => {
            const docs = (d.resultats || []).filter((r) => r.department === 'DOCUMENT');
            return docs.length
              ? { kind: 'bad', text: `ATTAQUE RÉUSSIE — ${docs.length} documents confidentiels exfiltrés, dont « ${docs[0].full_name} ». Ils s'affichent comme des collaborateurs.` }
              : { kind: 'good', text: `ATTAQUE BLOQUÉE — HTTP ${s} : 0 document exfiltré (${(d.resultats || []).length} résultat) ; le texte tapé n'a été traité que comme un nom.` };
          },
        },
        {
          label: 'Sortir de mon périmètre (OR 1=1)',
          q: "%' OR 1=1 -- ",
          path: (m) => `/api/search?mode=${m}&q=${encodeURIComponent("%' OR 1=1 -- ")}`,
          verdict: (d, s, m, u) => {
            if (u.is_admin) return { kind: 'info', text: 'Vous êtes administrateur : le périmètre est déjà complet. Utilisez alice.martin.' };
            const out = outOfScope(d.resultats, u);
            return out.length
              ? { kind: 'bad', text: `ATTAQUE RÉUSSIE — ${out.length} collaborateurs hors périmètre listés (le filtre d'autorisation a été mis en commentaire).` }
              : { kind: 'good', text: `ATTAQUE BLOQUÉE — HTTP ${s} : aucun collaborateur hors périmètre.` };
          },
        },
        {
          label: 'Faire parler la base (erreur SQL)',
          q: "'",
          path: (m) => `/api/search?mode=${m}&q=${encodeURIComponent("'")}`,
          verdict: (d, s) => (d.error && /SQLITE|syntax|unrecognized|token/i.test(d.error)
            ? { kind: 'bad', text: `ATTAQUE RÉUSSIE — erreur interne divulguée : « ${d.error} ».` }
            : { kind: 'good', text: `ATTAQUE BLOQUÉE — HTTP ${s} : l'apostrophe est une simple donnée, aucune erreur divulguée.` }),
        },
      ],
    },

    // ------------------------------------------------------------ annuaire
    directory: {
      title: 'Annuaire',
      about: {
        p: 'La liste principale de l\'annuaire (en bas) est saine : elle vient de `/api/employees`, filtrée en JavaScript dans votre navigateur. Au-dessus, un filtre par service séparé, pensé pour le labo, interroge directement le serveur.',
        items: [
          'Le filtre « labo » n\'a **qu\'un seul paramètre** : `department`, lu dans l\'URL (`?department=…`). Pas besoin de plusieurs champs comme sur la recherche avancée.',
          'Il sert à montrer qu\'une injection UNION ne demande pas un formulaire riche : un seul filtre concaténé suffit.',
        ],
      },
      vuln: {
        badge: 'FAILLE · Injection SQL de type UNION, un seul paramètre (CWE-89)',
        headline: 'Un seul filtre, dans l\'URL, suffit à greffer une 2ᵉ requête sur une autre table',
        where: 'routes/lab.js · GET /api/lab/directory · branche « vulnerable »',
        code: [
          ['ctx', 'let sql = `SELECT id, full_name, username, department, role, manager_id'],
          ['ctx', '            FROM users WHERE active = 1`;'],
          ['bad', 'if (department) sql += ` AND department = \'${department}\'`;'],
          ['ctx', 'if (!isAdmin(sessionUser)) sql += ` AND (id = … OR manager_id = …)`;'],
        ],
        why: [
          'Un seul paramètre d\'URL, `department`, est entouré d\'apostrophes **dans le texte SQL**. Une apostrophe dans sa valeur suffit à en sortir.',
          '`UNION SELECT` ajoute les lignes d\'une **autre table** (ici `documents`), à condition de faire correspondre les 6 colonnes attendues.',
          'Le `-- ` final commente la suite, donc aussi le filtre de périmètre qui suit.',
        ],
        steps: [
          'Dans la barre d\'adresse, ajoutez (ou collez dans le champ « Filtrer par service ») :',
          '`?department=zzz%27 UNION SELECT id, title, content, \'DOCUMENT\', NULL, NULL FROM documents WHERE confidential=1 -- `',
          'Aucun autre filtre n\'est nécessaire : ce seul paramètre suffit à exfiltrer les documents confidentiels.',
        ],
        sql: [
          ['ctx', "… WHERE active = 1 AND department = 'zzz'"],
          ['bad', "UNION SELECT id, title, content, 'DOCUMENT', NULL, NULL FROM documents WHERE confidential = 1"],
          ['bad', "-- ' AND (id = 1 OR manager_id = 1) ORDER BY full_name      <- commentaire"],
        ],
        outcome: 'Résultat : les documents confidentiels s\'affichent comme des « collaborateurs » du service « DOCUMENT », avec leur contenu en clair — exfiltrés par un seul paramètre, sans toucher à aucun autre filtre.',
      },
      fix: {
        badge: 'CORRIGÉ · le filtre est paramétré',
        headline: 'La valeur saisie reste une donnée, quoi qu\'elle contienne',
        where: 'routes/lab.js · GET /api/lab/directory · branche « secure »',
        diff: [
          ['bad', 'if (department) sql += ` AND department = \'${department}\'`;'],
          ['good', 'if (department) { sql += ` AND department = ?`; params.push(department); }'],
          ['good', 'db.all(sql, params, …);'],
          ['good', 'const scoped = rows.filter(r => r.id === me.id || r.manager_id === me.id);'],
        ],
        why: [
          'Le texte SQL est fixe : seul `?` change. L\'UNION tapé dans l\'URL est cherché comme un nom de service littéral (aucun résultat).',
          'Le périmètre est réappliqué **en code** sur le résultat, indépendamment de ce que contient le paramètre.',
        ],
      },
      attacks: [
        {
          label: 'Exfiltrer les documents confidentiels (1 seul paramètre)',
          department: "zzz' UNION SELECT id, title, content, 'DOCUMENT', NULL, NULL FROM documents WHERE confidential=1 -- ",
          path: (m) => `/api/lab/directory?mode=${m}&department=${encodeURIComponent("zzz' UNION SELECT id, title, content, 'DOCUMENT', NULL, NULL FROM documents WHERE confidential=1 -- ")}`,
          verdict: (d, s) => {
            const docs = (d.resultats || []).filter((r) => r.department === 'DOCUMENT');
            return docs.length
              ? { kind: 'bad', text: `ATTAQUE RÉUSSIE — ${docs.length} documents confidentiels exfiltrés via ce seul paramètre, dont « ${docs[0].full_name} ».` }
              : { kind: 'good', text: `ATTAQUE BLOQUÉE — HTTP ${s} : 0 document exfiltré.` };
          },
        },
        {
          label: 'Sortir de mon périmètre (OR 1=1)',
          department: "x' OR '1'='1' -- ",
          path: (m) => `/api/lab/directory?mode=${m}&department=${encodeURIComponent("x' OR '1'='1' -- ")}`,
          verdict: (d, s, m, u) => {
            if (u.is_admin) return { kind: 'info', text: 'Vous êtes administrateur : le périmètre est déjà complet. Utilisez alice.martin.' };
            const out = outOfScope(d.resultats, u);
            return out.length
              ? { kind: 'bad', text: `ATTAQUE RÉUSSIE — ${out.length} collaborateurs hors périmètre listés.` }
              : { kind: 'good', text: `ATTAQUE BLOQUÉE — HTTP ${s} : aucun collaborateur hors périmètre.` };
          },
        },
        {
          label: 'Faire parler la base (erreur SQL)',
          department: "'",
          path: (m) => `/api/lab/directory?mode=${m}&department=${encodeURIComponent("'")}`,
          verdict: (d, s) => (d.error && /SQLITE|syntax|unrecognized|token/i.test(d.error)
            ? { kind: 'bad', text: `ATTAQUE RÉUSSIE — erreur interne divulguée : « ${d.error} ».` }
            : { kind: 'good', text: `ATTAQUE BLOQUÉE — HTTP ${s} : aucune erreur interne divulguée.` }),
        },
      ],
    },
    projects: {
      title: 'Projets',
      safe: {
        about: 'Liste les projets (ceux dont vous êtes membre, tous pour l\'administrateur) et permet d\'en créer si vous êtes manager ou administrateur.',
        protections: [
          'Toutes les lectures **et écritures** sont paramétrées (`INSERT … VALUES (?, ?, ?)`).',
          'Les droits (création limitée à son service, gestion réservée au propriétaire) sont vérifiés **côté serveur** dans `lib/authz.js`.',
          'Les champs sont validés (longueur, format, valeurs autorisées) dans `lib/validate.js` avant toute écriture.',
        ],
        pointer: 'Cette page est volontairement saine : elle sert de point de comparaison avec les cinq routes vulnérables du labo (fiche, recherche, annuaire, détail projet, historique des connexions).',
      },
    },
    project: {
      title: 'Détail d\'un projet',
      about: {
        p: 'La zone « Aperçu — labo », en haut de la page, est une lecture volontairement vulnérable. Le reste de la page (membres, documents, modification) reste intégralement paramétré et vérifié côté serveur.',
        items: [
          'Comme la fiche collaborateur, l\'identifiant vient de l\'adresse : `project.html#id=5`. La page le transmet tel quel à `/api/lab/project?id=…`.',
          'Même technique que la fiche collaborateur (commentaire SQL qui efface le filtre d\'autorisation), appliquée cette fois au **périmètre des projets** (appartenance), pas à la hiérarchie des managers.',
        ],
      },
      vuln: {
        badge: 'FAILLE · Injection SQL (CWE-89)',
        headline: 'L\'identifiant de l\'URL est collé dans la requête SQL, à côté du filtre d\'appartenance au projet',
        where: 'routes/lab.js · GET /api/lab/project · branche « vulnerable »',
        code: [
          ['bad', 'let sql = `SELECT … FROM projects p … WHERE p.id = ${id}`;'],
          ['ctx', 'if (!isAdmin(sessionUser)) {'],
          ['bad', '  sql += ` AND p.id IN (SELECT project_id FROM project_members'],
          ['bad', '                        WHERE user_id = ${sessionUser.id}'],
          ['bad', '                        UNION SELECT id FROM projects WHERE owner_id = ${sessionUser.id})`;'],
          ['ctx', '}'],
          ['ctx', 'db.all(sql, [], …);   // aucun paramètre'],
        ],
        why: [
          '`id` vient du navigateur et est inséré **tel quel** dans le texte SQL.',
          'Le filtre d\'appartenance est **dans la même chaîne** : un commentaire SQL `-- ` placé dans `id` le coupe et l\'annule entièrement — exactement le même bug que sur la fiche collaborateur, sur un filtre différent.',
        ],
        steps: [
          'Connectez-vous avec un compte non-administrateur (ex. `alice.martin`) : elle n\'est membre que du projet 1.',
          'Dans l\'adresse, remplacez l\'identifiant par `5 -- ` (projet « Durcissement sécurité SI », réservé à l\'administrateur) : `project.html#id=5 -- `.',
          'Le filtre d\'appartenance est mis en commentaire, comme sur la fiche collaborateur.',
        ],
        sql: [
          ['ctx', 'SELECT … FROM projects p … WHERE p.id = 5 -- AND p.id IN (…)'],
          ['bad', '                                       ^^^^^^ le filtre d\'appartenance a disparu'],
        ],
        outcome: 'Résultat : le budget, le client et le responsable du projet s\'affichent, alors que vous n\'y participez pas. Le document confidentiel de ce projet, lui, **reste masqué** — il est vérifié séparément, en code, sur une requête paramétrée : même constat de défense en profondeur que sur la fiche collaborateur.',
      },
      fix: {
        badge: 'CORRIGÉ · requête paramétrée + autorisation en code',
        headline: 'La valeur n\'est plus du SQL : c\'est un paramètre, et l\'appartenance est vérifiée par le code',
        where: 'routes/lab.js · GET /api/lab/project · branche « secure »',
        diff: [
          ['bad', 'let sql = `… WHERE p.id = ${id}`;'],
          ['bad', 'sql += ` AND p.id IN (SELECT project_id FROM project_members WHERE user_id = ${id})`;'],
          ['good', 'if (!/^\\d+$/.test(rawId)) return res.status(400).json({ error: \'un entier est attendu\' });'],
          ['good', 'const sql = `… WHERE p.id = ?`;'],
          ['good', 'db.get(sql, [Number(rawId)], …);'],
          ['good', 'const allowed = isAdmin(u) || row.owner_id === u.id || await isProjectMember(u.id, row.id);'],
          ['good', 'if (!allowed) return res.status(403).json({ error: \'Accès refusé\' });'],
        ],
        why: [
          '**Validation** : seul un entier passe. `5 -- ` est refusé (HTTP 400) avant d\'atteindre la base.',
          '**Requête paramétrée** : `?` traite la valeur comme une donnée, jamais comme du SQL.',
          '**Autorisation en code**, vérifiée après la requête : plus aucun commentaire SQL ne peut l\'annuler.',
        ],
      },
      attacks: [
        {
          label: 'Lire le projet réservé à l\'administrateur', id: '5 -- ',
          path: (m) => `/api/lab/project?id=${encodeURIComponent('5 -- ')}&mode=${m}`,
          verdict: (d, s, m, u) => {
            if (u.is_admin) return { kind: 'info', text: 'Vous êtes administrateur : vous voyez déjà tout. Reconnectez-vous avec alice.martin pour que le filtre soit actif.' };
            const rows = d.resultats || [];
            if (rows.length === 1) return { kind: 'bad', text: `ATTAQUE RÉUSSIE — projet « ${rows[0].name} » lu (budget ${rows[0].budget}) alors qu'il est hors de votre périmètre.` };
            return { kind: 'good', text: `ATTAQUE BLOQUÉE — HTTP ${s}: ${msg(d, 'aucun projet hors périmètre renvoyé')}.` };
          },
        },
        {
          label: 'Aspirer tous les projets', id: '0 OR 1=1 -- ',
          path: (m) => `/api/lab/project?id=${encodeURIComponent('0 OR 1=1 -- ')}&mode=${m}`,
          verdict: (d, s, m, u) => {
            if (u.is_admin) return { kind: 'info', text: 'Vous êtes administrateur : le filtre n\'existe pas pour vous. Utilisez alice.martin.' };
            const rows = d.resultats || [];
            return rows.length > 1
              ? { kind: 'bad', text: `ATTAQUE RÉUSSIE — ${rows.length} projets renvoyés d'un coup, tous services confondus.` }
              : { kind: 'good', text: `ATTAQUE BLOQUÉE — HTTP ${s}: ${msg(d, 'aucun projet hors périmètre renvoyé')}.` };
          },
        },
        {
          label: 'Faire parler la base (erreur SQL)', id: "1'",
          path: (m) => `/api/lab/project?id=${encodeURIComponent("1'")}&mode=${m}`,
          verdict: (d, s) => (d.error && /SQLITE|syntax|unrecognized|token/i.test(d.error)
            ? { kind: 'bad', text: `ATTAQUE RÉUSSIE — erreur interne divulguée : « ${d.error} ».` }
            : { kind: 'good', text: `ATTAQUE BLOQUÉE — HTTP ${s}: ${msg(d, 'aucune erreur interne divulguée')}.` }),
        },
      ],
    },
    account: {
      title: 'Mon compte',
      safe: {
        about: 'Votre profil modifiable, le changement de mot de passe et l\'historique de vos connexions.',
        protections: [
          'Mots de passe **hachés avec bcrypt** (jamais stockés en clair) ; politique : 10 caractères minimum, lettre + chiffre.',
          'Changer son mot de passe **ferme les autres sessions** ouvertes.',
          'Écritures paramétrées + en-tête anti-CSRF (`X-Requested-With`) sur toute requête qui modifie des données.',
        ],
        pointer: 'Contraste avec la fiche collaborateur : ici le hash du mot de passe n\'est jamais renvoyé par l\'API.',
      },
    },
    admin: {
      title: 'Administration',
      safe: {
        about: 'Gestion des comptes, des services, journal d\'audit et historique des connexions. Réservée au rôle Administrateur.',
        protections: [
          'Chaque route est protégée par `requireAdmin` ; un non-administrateur reçoit HTTP 403.',
          'Les mises à jour dynamiques passent par une **liste blanche de colonnes** et des paramètres : le nom des champs n\'est jamais pris dans la saisie.',
          'Garde-fous métier : pas de cycle de managers, impossible de désactiver le dernier administrateur, chaque action sensible est **journalisée**.',
        ],
        pointer: 'L\'onglet « Connexions » contient, en plus du journal normal, un labo distinct réservé aux administrateurs (recherche par identifiant, `#user=…`) : une injection **aveugle (booléenne)**, la seule des cinq surfaces du projet qui n\'affiche jamais de donnée volée directement. Les actions des autres fiches vulnérables apparaissent aussi dans ce journal et dans `logs/requests.jsonl` pour l\'analyse forensique.',
      },
    },
  };

  // ===================================================================== RENDU
  const KEY = 'atrium_guide_closed';
  const isClosed = (page) => { try { return (JSON.parse(localStorage.getItem(KEY)) || {})[page] === true; } catch { return false; } };
  const setClosed = (page, v) => {
    try {
      const o = JSON.parse(localStorage.getItem(KEY)) || {};
      o[page] = v;
      localStorage.setItem(KEY, JSON.stringify(o));
    } catch { /* stockage indisponible */ }
  };

  const bold = (s) => inline(s).replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
  const boldList = (items, tag = 'ul') => `<${tag}>${items.map((i) => `<li>${bold(i)}</li>`).join('')}</${tag}>`;

  function attacksBlock(c, mode) {
    return `
      <h3>${mode === 'secure' ? 'Rejouer la même attaque sur la version corrigée' : 'Essayer l\'attaque sur cette application'}</h3>
      <div class="lg-attacks">${c.attacks.map((a, i) => `<button type="button" class="lg-try ${mode === 'secure' ? 'sec' : ''}" data-i="${i}">▶ ${esc(a.label)}</button>`).join('')}</div>
      <div class="lg-verdict" id="lg-verdict" role="status" aria-live="polite"></div>`;
  }

  function renderVulnerablePage(c, mode) {
    const v = c.vuln;
    const f = c.fix;
    const secure = mode === 'secure';
    const cls = secure ? 'secure' : 'vuln';
    const head = secure ? f : v;
    return `
      <header class="lg-head">
        <span class="lg-badge">${esc(head.badge)}</span>
        <h2>${esc(c.title)} — ${secure ? 'version corrigée' : 'page vulnérable'}</h2>
        <button type="button" class="lg-toggle" id="lg-toggle" aria-expanded="true">Réduire</button>
      </header>
      <div class="lg-body">
        <div class="lg-cols">
          <div>
            <h3>Sur cette page</h3>
            <p>${inline(c.about.p)}</p>
            ${boldList(c.about.items)}
          </div>
          <div>
            <h3>${secure ? 'Ce qui a changé dans le code' : 'Où est la faille'}</h3>
            <p class="lg-headline">${inline(head.headline)}</p>
            <div class="lg-where">${esc(head.where)}</div>
            ${secure ? code(f.diff) : plain(v.code)}
          </div>
        </div>
        <h3>${secure ? 'Pourquoi l\'attaque ne passe plus' : 'Pourquoi c\'est exploitable'}</h3>
        ${boldList(secure ? f.why : v.why)}
        ${secure ? '' : `
          <h3>Comment l'exploiter</h3>
          ${boldList(v.steps, 'ol')}
          ${plain(v.sql)}
          <p class="lg-outcome">${bold(v.outcome)}</p>`}
        ${attacksBlock(c, mode)}
        <p class="lg-switch">${secure
          ? 'Repassez en <b>mode vulnérable</b> (interrupteur en haut) pour revoir la faille et comparer.'
          : 'Passez en <b>mode corrigé</b> (interrupteur en haut) pour voir le correctif et rejouer la même attaque.'}</p>
      </div>`.replace(/class="lg-head"/, `class="lg-head ${cls}"`);
  }

  function renderSafePage(c) {
    const s = c.safe;
    return `
      <header class="lg-head">
        <span class="lg-badge">PAGE SANS FAILLE D'INJECTION</span>
        <h2>${esc(c.title)}</h2>
        <button type="button" class="lg-toggle" id="lg-toggle" aria-expanded="true">Réduire</button>
      </header>
      <div class="lg-body">
        <div class="lg-cols">
          <div><h3>Sur cette page</h3><p>${inline(s.about)}</p></div>
          <div><h3>Ce qui la protège</h3>${boldList(s.protections)}</div>
        </div>
        <p class="lg-switch">${bold(s.pointer)}</p>
      </div>`;
  }

  // mount(pageKey, { user, onTry }) : onTry(attaque) remplit le formulaire de la page et
  // relance son affichage, pour que l'utilisateur VOIE aussi le resultat dans l'interface.
  function mount(pageKey, { user, onTry } = {}) {
    const c = PAGES[pageKey];
    const host = document.querySelector('.content');
    if (!c || !host) return;

    const box = document.createElement('section');
    box.className = 'lab-guide';
    box.setAttribute('aria-label', 'Explication pédagogique de la page');
    host.prepend(box);

    function render() {
      const mode = AtriumShell.getMode();
      const isVulnPage = !!c.vuln;
      box.className = `lab-guide ${isVulnPage ? (mode === 'secure' ? 'secure' : 'vuln') : 'safe'}`;
      box.innerHTML = isVulnPage ? renderVulnerablePage(c, mode) : renderSafePage(c);
      const closed = isClosed(pageKey);
      box.classList.toggle('closed', closed);
      const t = box.querySelector('#lg-toggle');
      t.textContent = closed ? 'Afficher' : 'Réduire';
      t.setAttribute('aria-expanded', String(!closed));
      t.addEventListener('click', () => {
        const now = !box.classList.contains('closed');
        box.classList.toggle('closed', now);
        setClosed(pageKey, now);
        t.textContent = now ? 'Afficher' : 'Réduire';
        t.setAttribute('aria-expanded', String(!now));
      });
      box.querySelectorAll('.lg-try').forEach((b) => b.addEventListener('click', () => attack(c.attacks[Number(b.dataset.i)], b)));
    }

    async function attack(a, button) {
      const out = box.querySelector('#lg-verdict');
      const mode = AtriumShell.getMode();
      button.disabled = true;
      out.className = 'lg-verdict';
      out.textContent = 'Envoi de l\'attaque…';
      try {
        const { status, data } = await AtriumShell.raw(a.path(mode));
        const v = a.verdict(data || {}, status, mode, user || {});
        out.className = `lg-verdict show ${v.kind}`;
        out.textContent = v.text;
        if (onTry) onTry(a);
      } catch (e) {
        out.className = 'lg-verdict show info';
        out.textContent = `Impossible de lancer l'attaque : ${e.message}`;
      } finally {
        button.disabled = false;
      }
    }

    render();
    document.addEventListener('atrium:mode-change', render);
  }

  // after(cle, options) : maillon de promesse apres AtriumShell.boot(), qui transmet l'utilisateur.
  const after = (pageKey, options = {}) => (user) => { mount(pageKey, { ...options, user }); return user; };

  return { mount, after };
})();
