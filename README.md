# Atrium — Labo « Injection SQL basée sur le DOM »

Labo pédagogique pour le cours de Sécurité des bases de données (IFRI). Une application
d'annuaire interne fictive, « Atrium », avec un vrai modèle d'autorisation : chaque compte ne
voit que son propre périmètre. Le point de la démonstration n'est pas seulement « l'ID devient
du SQL », mais **l'injection contourne le contrôle d'accès lui-même**.

**À exécuter uniquement en local.** Données entièrement fictives.

Atrium est une application complète (comptes, sessions, projets, documents, administration)
dans laquelle **seules cinq routes en lecture sont volontairement vulnérables** — voir
« Où se jouent les failles ». Tout le reste (connexion, écritures, administration) est écrit
proprement : requêtes paramétrées, sessions serveur, droits vérifiés côté serveur.

## Installation

Node.js ≥ 22 requis.

```
npm install
npm start
npm test        # 50 tests (auth, droits, labo, persistance)
```

Puis ouvrir http://localhost:3000 et se connecter. En environnement de développement, l'écran
de connexion propose les **6 comptes de démonstration** : un clic pré-remplit identifiant et
mot de passe.

| Compte | Identifiant |
|---|---|
| Alice Martin | `alice.martin` |
| Julien Picard | `julien.picard` |
| Bassirou Koffi | `bassirou.koffi` |
| Nadia Benali | `nadia.benali` |
| Fatou Diarra | `fatou.diarra` |
| Admin Système | `admin` |

Mot de passe commun à ces 6 comptes : **`Password123`** (`DEMO_PASSWORD` dans `db.js`).

### Configuration

Variables d'environnement, ou fichier `.env` (modèle : `.env.example`) ; la liste complète est
dans `config.js`. Les principales : `PORT`, `NODE_ENV`, `DB_PATH` (fichier SQLite,
`:memory:` pour une base jetable), `SESSION_TTL_HOURS`, `COOKIE_SECURE`, `DEMO_ACCOUNTS`
(affiche les comptes ci-dessus sur l'écran de connexion — jamais hors labo),
`LOGIN_MAX_ATTEMPTS`.

### Persistance

La base est un fichier (`data/atrium.db` par défaut). Le schéma est créé et les données de
démonstration insérées **au premier démarrage seulement** : modifications, comptes créés et
projets survivent aux redémarrages. `npm run db:reset` (serveur arrêté) supprime le fichier
pour repartir de l'état initial — à faire avant une soutenance, car les scénarios ci-dessous
supposent les données d'origine (4 documents confidentiels, etc.).

## Authentification et sessions

Connexion par identifiant + mot de passe (bcrypt). Le serveur pose un cookie `atrium_sid`
(`HttpOnly`, `SameSite=Lax`, `Secure` si `COOKIE_SECURE`) portant un jeton aléatoire ; seule
son empreinte SHA-256 est stockée (table `sessions`). Le compte courant est relu à chaque
requête : désactiver un compte ou changer un mot de passe ferme ses sessions immédiatement.
Autres protections : limitation des essais (`429` après 5 échecs par IP + identifiant), message
d'erreur identique pour « mauvais mot de passe » et « identifiant inconnu », en-tête
anti-CSRF `X-Requested-With` obligatoire sur toute écriture, historique des connexions.

L'ancien paramètre `?as=<id>` n'existe plus : l'identité vient uniquement du cookie.

## Modèle d'autorisation

Trois profils, plus la notion de propriétaire de projet (`lib/authz.js`) :

| Profil | Peut |
|---|---|
| **Collaborateur** | voir sa fiche et ses projets ; modifier ses coordonnées et son mot de passe ; ajouter des documents aux projets où il est membre |
| **Manager** (a au moins un subordonné direct actif — calculé, pas stocké) | + voir les fiches de ses subordonnés ; créer des projets **dans son service** |
| **Administrateur** | tout voir ; gérer comptes, services, projets ; consulter le journal d'audit |
| **Propriétaire d'un projet** | modifier/supprimer le projet, gérer ses membres, modifier tout document du projet |

Un document peut être modifié par son auteur, le propriétaire du projet ou un administrateur.
Garde-fous : pas de cycle dans la hiérarchie `manager_id`, impossible de désactiver son propre
compte ou de retirer le dernier administrateur, un service utilisé ne peut pas être supprimé.

La règle de lecture de la fiche est : **un compte voit sa propre fiche, plus celles de ses
subordonnés directs** ; l'Administrateur voit tout. Un second niveau d'autorisation porte sur
les **documents de projet** : un document marqué `confidential` n'est visible que pour les
membres du projet concerné (ou l'Administrateur), indépendamment du périmètre « fiche ». Voir
`isDocVisible()` dans `routes/lab.js`.

| Compte | Périmètre « fiches » |
|---|---|
| Alice Martin | elle-même uniquement |
| Julien Picard (son manager) | lui-même + Alice |
| Bassirou, Nadia, Fatou | eux-mêmes uniquement |
| Admin Système | tout le monde |

## Pages

`login`, `directory` (annuaire — **faille n°3**, filtre par service), `search` (recherche
avancée — **faille n°2**), `profile` (fiche — **faille n°1**), `projects` (liste, création),
`project` (détail : membres, documents — **faille n°4**, aperçu), `account` (mes
informations, mot de passe, mes connexions), `admin` (comptes, services, journal d'audit,
connexions — administrateurs uniquement ; onglet Connexions = **faille n°5**, aveugle).

## Schéma de données

Au-delà de `users`, la base relie plusieurs tables (`db.js`) pour que les requêtes ressemblent
à une vraie application plutôt qu'à un simple `WHERE id = ...` :

- `departments` — service, budget, site.
- `projects` — rattaché à un service (`department_id`), avec client, budget, statut,
  propriétaire (`owner_id`).
- `project_members` — qui travaille sur quel projet (table de jointure).
- `documents` — notes de projet, certaines `confidential` (grilles salariales, rapports d'audit,
  tarifs négociés, résultats de pentest), avec auteur et dates.
- `login_history` — trace de connexion (réussies et échecs), pour la partie forensique.
- `sessions` — sessions ouvertes (empreinte du jeton, expiration).
- `audit_log` — journal de toutes les actions d'écriture et des échecs de connexion.

La fiche collaborateur (`/api/profile`) affiche maintenant, en plus de l'identité, la liste des
projets du collaborateur (JOIN `project_members` → `projects` → `departments`) et les documents
de chaque projet — redigés (`content: null`) si confidentiels et hors périmètre.

## Où se jouent les failles

Cinq routes (`routes/lab.js`), chacune avec une implémentation **Vulnérable** et **Corrigée**,
choisies via le sélecteur **Mode démo** visible dans l'interface. Ce sont les **seules** à
construire du SQL par concaténation : toutes les routes d'écriture sont paramétrées, et
l'injection ne s'exerce que sous la session de l'utilisateur connecté (elle contourne son
périmètre, pas l'authentification). Elles couvrent trois techniques et deux vecteurs
(DOM — `location.hash` — et URL — paramètres `?...`), répartis sur (presque) toutes les
pages de lecture de l'application :

### `/api/profile` — contournement de l'autorisation (commentaire SQL)

- **Vulnérable** : l'identifiant ET le filtre d'autorisation sont concaténés dans le **même**
  texte SQL : `WHERE u.id = ${id} AND (u.id = ${moi} OR u.manager_id = ${moi})`. Un commentaire
  SQL (`-- `) dans l'identifiant coupe la requête avant ce filtre — l'autorisation ne s'applique
  plus du tout, pas seulement le filtre par identifiant.
- **Corrigé** : la fiche est récupérée par requête paramétrée, puis l'autorisation est vérifiée
  **dans le code**, séparément. Rien dans l'URL ne peut influencer cette vérification.

Remarque : même quand ce contournement fonctionne, les **documents confidentiels** restent
redigés s'ils appartiennent à un projet hors du périmètre de l'attaquant — ce niveau
d'autorisation est vérifié séparément, en code, sur une requête elle-même paramétrée. C'est un
bon exemple de défense en profondeur : une des deux couches cède, l'autre tient.

### `/api/search` — exfiltration inter-tables (UNION-based)

Recherche avancée (nom, service, statut de projet) construite en concaténant chaque filtre dans
le SQL — le pattern vulnérable le plus courant dans les vraies applications, pas seulement un
ID dans une URL.

- **Vulnérable** : une apostrophe dans le champ « Nom » échappe au littéral `LIKE '%...%'` et
  permet d'ajouter un `UNION SELECT` qui pioche dans une **autre table**. Exemple testé :
  ```
  zzz%' UNION SELECT id, title, 'Document confidentiel', 'N/A', NULL FROM documents WHERE confidential = 1 -- 
  ```
  Résultat : les 4 documents confidentiels de l'entreprise (grilles de salaire, rapport d'audit,
  tarifs clients, résultats de pentest) s'affichent dans les résultats de recherche d'Alice,
  déguisés en « collaborateurs » — alors que son périmètre ne devrait contenir qu'elle-même.
- **Corrigé** : chaque filtre est paramétré (`?`). Une apostrophe dans l'entrée reste une donnée
  littérale ; impossible de faire basculer la requête vers un `UNION SELECT`.

### `/api/lab/directory` — exfiltration par un seul paramètre d'URL (UNION-based)

Filtre par service de l'annuaire (`directory.html`), ajouté spécifiquement pour montrer qu'un
UNION-based n'a besoin que d'**un seul** paramètre concaténé, sans formulaire à plusieurs
filtres comme sur `/api/search`.

- **Vulnérable** : `?department=...` est collé tel quel dans `WHERE department = '${department}'`.
  Le même payload `UNION SELECT` que sur `/api/search` (adapté à 6 colonnes) exfiltre les
  documents confidentiels, atteignable directement via l'URL : `directory.html?department=...`.
- **Corrigé** : paramètre lié (`?`), périmètre réappliqué en code sur le résultat.

### `/api/lab/project` — contournement d'autorisation, deuxième modèle (commentaire SQL)

Aperçu en lecture d'un projet (`project.html`), **même technique** que `/api/profile`
(commentaire SQL qui efface le filtre d'autorisation) mais appliquée à un modèle
d'autorisation différent : l'appartenance au projet (`project_members`/`owner_id`), pas la
hiérarchie `manager_id`. Source DOM : `project.html#id=...`, comme la fiche collaborateur.
Montre que le même bug (filtre de périmètre concaténé dans le texte SQL) se reproduit partout
où ce motif est codé deux fois indépendamment.

- **Vulnérable** : `WHERE p.id = ${id} AND p.id IN (SELECT project_id FROM project_members
  WHERE user_id = ${moi} UNION SELECT id FROM projects WHERE owner_id = ${moi})`. Un commentaire
  SQL dans `id` efface tout ce qui suit, y compris ce filtre d'appartenance.
- **Corrigé** : requête paramétrée, puis appartenance vérifiée en code (`isProjectMember`).
- Comme sur la fiche collaborateur, le document confidentiel du projet reste masqué même après
  contournement : son autorisation est vérifiée séparément (défense en profondeur).

### `/api/lab/login-history` — technique aveugle (booléenne), réservée aux administrateurs

Recherche dans l'historique de connexion par identifiant, onglet **Connexions** de
l'administration, lue dans l'URL (`#user=...`). Contrairement aux quatre routes ci-dessus,
**aucune donnée d'une autre table n'est jamais affichée directement** : seul le nombre de
lignes renvoyées (0 ou plus) sert de signal — la famille « blind » documentée en théorie dans
`docs/techniques-complementaires.md`, ici réellement câblée. Démontre qu'un outil
d'administration peut lui aussi être une cible, par exemple via un lien piégé envoyé à un
administrateur.

- **Vulnérable** : `WHERE u.username = '${user}'`. Payload d'exemple :
  `admin' AND SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='$' -- ` — une
  réponse non vide confirme le caractère, une réponse vide l'infirme. Le labo ne scripte
  volontairement pas le sondage caractère par caractère (voir
  `docs/techniques-complementaires.md`, section « Pourquoi le blind et le temporel ne sont pas
  scriptés ici »).
- **Corrigé** : paramètre lié ; la chaîne reste un nom d'utilisateur littéral.

## Scénario de démonstration (pour la soutenance)

### Partie 1 — contournement d'autorisation sur la fiche

Après `npm run db:reset`, connectez-vous en tant qu'**Alice Martin** (son périmètre ne contient
qu'elle-même).

1. **Accès normal** — `profile.html#id=1` : sa propre fiche s'affiche, avec ses projets.
2. **Accès hors périmètre, sans injection** — changez l'URL en `#id=3` (Nadia Benali, dans un
   autre service). Toujours en mode Vulnérable : **aucun résultat**. Le filtre d'autorisation,
   bien présent dans la requête, fait son travail. Montrez-le dans le panneau développeur.
3. **Le contournement** — changez l'URL en `#id=3 -- ` (avec l'espace après `--`). La fiche de
   Nadia s'affiche. Ouvrez le panneau développeur : la requête montre que `-- ` a transformé
   tout ce qui suit en commentaire SQL, effaçant le filtre d'autorisation. Notez que son document
   de projet confidentiel reste masqué — cette autorisation-là tient toujours.
4. **Encore plus large** — `#id=0 OR 1=1 -- ` renvoie toutes les fiches de l'entreprise,
   mots de passe (hachés) inclus — alors qu'Alice ne devrait voir qu'elle-même.
5. **Même attaque, mode Corrigé** — basculez le sélecteur, gardez `#id=0 OR 1=1 -- ` : rejeté au
   format avant même d'atteindre la base. Essayez aussi `#id=3` (un ID valide mais hors
   périmètre) en mode Corrigé : `403 Accès refusé`, propre, peu importe ce qui est tapé dans
   l'URL.

### Partie 2 — exfiltration inter-tables sur la recherche avancée

Toujours en tant qu'Alice, allez sur **Recherche avancée**.

6. **Recherche normale** — tapez « a » dans Nom : seule la fiche d'Alice apparaît (périmètre
   respecté).
7. **L'injection UNION** — en mode Vulnérable, collez dans le champ Nom :
   `zzz%' UNION SELECT id, title, 'Document confidentiel', 'N/A', NULL FROM documents WHERE confidential = 1 -- `
   Les 4 documents confidentiels de l'entreprise apparaissent comme des « résultats
   collaborateurs ». Montrez la requête dans le panneau développeur : le `UNION SELECT` ajoute
   des lignes d'une table que la page n'était jamais censée exposer.
8. **Même recherche, mode Corrigé** — basculez le sélecteur, retentez la même chaîne : aucun
   résultat suspect, le texte est traité comme une donnée, pas comme du SQL.

### Partie 3 — un seul paramètre d'URL suffit (annuaire)

Sur **Annuaire**, dans le champ « Filtrer par service (labo) » ou directement dans l'adresse,
collez :
```
?department=zzz' UNION SELECT id, title, content, 'DOCUMENT', NULL, NULL FROM documents WHERE confidential=1 -- 
```
Les documents confidentiels apparaissent, exfiltrés par ce **seul** paramètre — sans toucher à
aucun autre filtre, contrairement à la recherche avancée.

### Partie 4 — même faille, deuxième modèle d'autorisation (projet)

Toujours en tant qu'Alice, ouvrez un projet dont elle n'est pas membre en changeant l'adresse en
`project.html#id=5 -- ` (projet réservé à l'administrateur). L'aperçu « labo » en haut de la
page affiche son budget et son client ; son document reste masqué (défense en profondeur).

### Partie 5 — technique aveugle (admin uniquement)

Connectez-vous en `admin`, ouvrez **Administration → Connexions**, et dans le bloc « labo »,
comparez `admin' AND 1=1 -- ` (des lignes reviennent) à `admin' AND 1=2 -- ` (aucune ligne) :
la différence est le signal qu'une injection aveugle exploite, caractère par caractère, sans
jamais afficher directement de donnée volée.

### Conclusion orale

« L'application avait bien un contrôle d'accès, à deux niveaux (fiche et documents). L'injection
n'a pas évité ce contrôle, elle l'a supprimé de la requête elle-même — ou elle a ajouté une
requête entière que l'application n'avait pas prévue. La correction déplace la logique
sensible hors du texte SQL : paramètres liés, autorisation vérifiée en code. Dans les deux cas,
l'entrée utilisateur ne peut plus changer la structure de la requête. »

9. (Optionnel, détection) `npm run forensic` relit `logs/requests.jsonl` et retrouve les
   tentatives grâce à leurs motifs caractéristiques (`OR 1=1`, `UNION SELECT`, commentaires `--`).

## Structure

- `server.js` (démarrage) et `app.js` (assemblage Express) ; `config.js` (environnement).
- `routes/lab.js` — **les cinq surfaces vulnérables** : `/api/profile` (la fiche + ses
  projets/documents), `/api/search` (recherche avancée multi-tables), `/api/lab/directory`
  (filtre service, un seul paramètre), `/api/lab/project` (aperçu projet, même technique que
  `/api/profile`) et `/api/lab/login-history` (aveugle, administrateurs uniquement) —
  vulnérables ou corrigées selon `?mode=`.
- `routes/auth.js` (connexion, `/api/me`, mot de passe), `routes/directory.js` (annuaire,
  services, comptes de démo), `routes/projects.js` (projets, membres, documents),
  `routes/admin.js` (comptes, services, journaux). Toutes paramétrées.
- `lib/` — `authz.js` (règles de droits), `validate.js` (validation des entrées), `audit.js`,
  `http.js` (erreurs, enveloppe async).
- `middleware/session.js` (sessions, limiteur d'essais), `security.js` (en-têtes, anti-CSRF),
  `logger.js` + `forensic/analyze-logs.js` (`npm run forensic`) — journalisation et détection a
  posteriori des motifs d'injection.
- `db.js` — base SQLite persistante : schéma, données de démonstration (6 collaborateurs,
  hiérarchie `manager_id`, mots de passe bcrypt ; projets, documents dont 4 confidentiels).
- `public/` — 8 pages (voir « Pages »), `styles.css`, `app-shell.js` (API, échappement HTML,
  barre latérale, mode démo), `lab-guide.js` (cadre pédagogique affiché en haut de chaque page :
  explication de la page, code vulnérable/corrigé, et boutons pour lancer chaque attaque
  directement depuis l'interface). `profile.html` et `project.html` lisent l'identifiant dans
  `location.hash` (le DOM) — c'est la source des failles n°1 et n°4. Toute valeur issue de la
  base est échappée avant affichage.
- `tests/` — `npm test` : `auth` (sessions, limitation, mot de passe), `access` (droits et
  logique métier), `lab` (non-régression des cinq failles : elles doivent rester exploitables en
  mode vulnérable et fermées en mode corrigé), `persistence`.
- `scripts/reset-db.js` — `npm run db:reset`.
- `docs/techniques-complementaires.md` — temporel (théorique ; in-band, UNION-based et blind
  booléen sont implémentés concrètement sur les cinq routes de `routes/lab.js`, voir plus haut).

## Pour le rapport

- Capturer les étapes des cinq scénarios ci-dessus, panneau développeur ouvert à chaque fois (ou
  les cadres pédagogiques de chaque page, qui donnent directement le même détail et un bouton
  pour rejouer l'attaque).
- Documenter le chemin complet pour chaque faille : source (DOM, `location.hash` ou champ de
  formulaire, ou paramètre d'URL) → transit (`fetch`) → sink (SQL, concaténation du filtre **et**
  souvent d'un filtre d'autorisation) → retour (JSON affiché, ou simple présence/absence de
  résultat pour la variante aveugle).
- Insister sur trois points centraux :
  1. une injection SQL peut annuler un contrôle d'accès applicatif entier dès que ce contrôle
     est exprimé dans la même requête que l'entrée non validée (`/api/profile`, `/api/lab/project`) ;
  2. une injection peut faire apparaître des données d'une table que la requête d'origine ne
     devait jamais toucher, via `UNION SELECT` (`/api/search`, `/api/lab/directory`) — y compris
     quand cette table contient des données volontairement cloisonnées (documents
     confidentiels), et qu'un seul paramètre concaténé suffit, sans formulaire riche ;
  3. même sans aucune donnée affichée directement, une injection reste exploitable par un simple
     signal vrai/faux (`/api/lab/login-history`) — et une surface réservée aux administrateurs
     n'est pas à l'abri pour autant.
- Mentionner le scénario du lien piégé (un attaquant envoie `profile.html#id=... -- ` ou
  `project.html#id=... -- ` à une victime connectée, pour voler des fiches ou des projets hors
  de son propre périmètre) comme vecteur de diffusion possible — non implémenté ici (XSS /
  exfiltration, sujet distinct).
- Références à citer : CWE-89 (injection SQL), CWE-285 / CWE-639 (contrôle d'accès incorrect /
  IDOR, pour le volet autorisation contournée), CWE-209 (fuite de message d'erreur SQL brut).

## Avertissement

Code volontairement vulnérable à des fins pédagogiques. Ne jamais déployer cette application en
l'état sur un serveur accessible depuis l'extérieur, et ne jamais réutiliser les branches
« vulnérable » de `/api/profile`, `/api/search`, `/api/lab/directory`, `/api/lab/project` et
`/api/lab/login-history` dans un projet réel. Hors de ces cinq routes, l'application n'est pas
pour autant prête pour la production : pas de HTTPS ni de Content-Security-Policy (les pages
utilisent des scripts inline), limiteur d'essais en mémoire (un par processus), pas de sauvegarde
ni de rotation des journaux.
