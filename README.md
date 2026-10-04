# Atrium — Labo « Injection SQL basée sur le DOM »

Labo pédagogique pour le cours de Sécurité des bases de données (IFRI). Une application
d'annuaire interne fictive, « Atrium », avec un vrai modèle d'autorisation : chaque compte ne
voit que son propre périmètre. Le point de la démonstration n'est pas seulement « l'ID devient
du SQL », mais **l'injection contourne le contrôle d'accès lui-même**.

**À exécuter uniquement en local.** Données entièrement fictives.

Atrium est une application complète (comptes, sessions, projets, documents, administration)
dans laquelle **seules deux routes en lecture sont volontairement vulnérables** — voir
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

`login`, `directory` (annuaire), `profile` (fiche — **faille n°1**), `search` (recherche
avancée — **faille n°2**), `projects` (liste, création), `project` (détail : membres,
documents), `account` (mes informations, mot de passe, mes connexions), `admin` (comptes,
services, journal d'audit, connexions — administrateurs uniquement).

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

Deux routes (`routes/lab.js`), chacune avec une implémentation **Vulnérable** et **Corrigée**,
choisies via le sélecteur **Mode démo** visible dans l'interface. Ce sont les **seules** à
construire du SQL par concaténation : toutes les routes d'écriture sont paramétrées, et
l'injection ne s'exerce que sous la session de l'utilisateur connecté (elle contourne son
périmètre, pas l'authentification) :

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
- `routes/lab.js` — **les deux surfaces vulnérables** : `/api/profile` (la fiche + ses
  projets/documents) et `/api/search` (recherche avancée multi-tables), vulnérables ou
  corrigées selon `?mode=`.
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
  barre latérale, mode démo). `profile.html` lit l'identifiant dans `location.hash` (le DOM) —
  c'est la source de la faille n°1. Toute valeur issue de la base est échappée avant affichage.
- `tests/` — `npm test` : `auth` (sessions, limitation, mot de passe), `access` (droits et
  logique métier), `lab` (non-régression des deux failles : elles doivent rester exploitables en
  mode vulnérable et fermées en mode corrigé), `persistence`.
- `scripts/reset-db.js` — `npm run db:reset`.
- `docs/techniques-complementaires.md` — blind booléen, time-based (théorique ; le UNION-based
  est maintenant implémenté concrètement sur `/api/search`, voir plus haut).

## Pour le rapport

- Capturer les étapes des deux scénarios ci-dessus, panneau développeur ouvert à chaque fois.
- Documenter le chemin complet pour chaque faille : source (DOM, `location.hash` ou champ de
  formulaire) → transit (`fetch`) → sink (SQL, concaténation du filtre **et** souvent d'un
  filtre d'autorisation) → retour (JSON affiché).
- Insister sur deux points centraux :
  1. une injection SQL peut annuler un contrôle d'accès applicatif entier dès que ce contrôle
     est exprimé dans la même requête que l'entrée non validée (`/api/profile`) ;
  2. une injection peut faire apparaître des données d'une table que la requête d'origine ne
     devait jamais toucher, via `UNION SELECT` (`/api/search`) — y compris quand cette table
     contient des données volontairement cloisonnées (documents confidentiels).
- Mentionner le scénario du lien piégé (un attaquant envoie `profile.html#id=... -- ` à une
  victime connectée, pour voler des fiches hors du périmètre de la victime elle-même) comme
  vecteur de diffusion possible — non implémenté ici (XSS / exfiltration, sujet distinct).
- Références à citer : CWE-89 (injection SQL), CWE-285 / CWE-639 (contrôle d'accès incorrect /
  IDOR, pour le volet autorisation contournée), CWE-209 (fuite de message d'erreur SQL brut).

## Avertissement

Code volontairement vulnérable à des fins pédagogiques. Ne jamais déployer cette application en
l'état sur un serveur accessible depuis l'extérieur, et ne jamais réutiliser les branches
« vulnérable » de `/api/profile` et `/api/search` dans un projet réel. Hors de ces deux routes,
l'application n'est pas pour autant prête pour la production : pas de HTTPS ni de
Content-Security-Policy (les pages utilisent des scripts inline), limiteur d'essais en mémoire
(un par processus), pas de sauvegarde ni de rotation des journaux.
