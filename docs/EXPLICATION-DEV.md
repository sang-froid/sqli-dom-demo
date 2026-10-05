# L'injection SQL « basée sur le DOM », expliquée pour les développeurs

*Public visé : des développeurs à l'aise avec JavaScript, HTTP et SQL, mais pas forcément
familiers des termes de sécurité (CWE, « blind SQLi », etc.). Ce document explique le mécanisme
avec du code, sans supposer de bagage sécurité préalable.*

---

## 1. Le problème de base : concaténer au lieu de paramétrer

Quand on construit une requête SQL en collant des morceaux de texte, y compris une valeur reçue
du client, on obtient ceci :

```js
// Côté serveur
const id = req.query.id;           // ex. "3"
const sql = `SELECT * FROM users WHERE id = ${id}`;
db.all(sql, [], callback);
```

Tant que `id` vaut `3`, la requête exécutée est `SELECT * FROM users WHERE id = 3` : rien
d'anormal. Le problème, c'est que **rien n'empêche `id` de contenir autre chose qu'un nombre**. Si
le client envoie `id=3 OR 1=1`, la requête devient :

```sql
SELECT * FROM users WHERE id = 3 OR 1=1   -- renvoie TOUTES les lignes
```

Le moteur SQL ne fait aucune différence entre « le texte que le développeur a écrit » et « le
texte qui vient de l'utilisateur » : au moment de l'exécution, tout ça n'est qu'une seule chaîne de
caractères qu'il interprète du début à la fin. C'est la cause racine de toute injection SQL,
peu importe la variante (`CWE-89` si vous cherchez la référence standard).

### La variante qui fait mal : effacer un contrôle d'accès, pas juste une valeur

Dans beaucoup d'applications réelles, un filtre d'autorisation est ajouté **dans le même texte
SQL** que l'identifiant demandé :

```js
let sql = `SELECT * FROM users WHERE id = ${id}`;
if (!isAdmin(sessionUser)) {
  sql += ` AND (id = ${sessionUser.id} OR manager_id = ${sessionUser.id})`;
}
```

Si `id` vaut `3`, tout va bien : la seconde condition restreint bien le résultat au périmètre de
l'utilisateur connecté. Mais si `id` vaut `3 -- ` (un commentaire SQL), la requête devient :

```sql
SELECT * FROM users WHERE id = 3 --  AND (id = 1 OR manager_id = 1)
```

Tout ce qui suit `--` est ignoré par le moteur SQL. **Le filtre d'autorisation n'est jamais
exécuté**, alors qu'il fonctionnait très bien dans tous les autres cas. Ce n'est plus seulement
une fuite de données ponctuelle : c'est le contrôle d'accès lui-même qui disparaît, parce qu'il
était écrit au mauvais endroit (dans une chaîne SQL manipulable) plutôt que dans le code
applicatif.

## 2. Ce qui est spécifique à « basé sur le DOM »

Le point précédent (injection par concaténation) est vrai que la valeur vienne d'un `req.query`
côté serveur ou d'ailleurs. Ce qui change avec le DOM, c'est **l'origine de la valeur côté
client**, avant même qu'elle n'atteigne une requête HTTP.

### Source vs sink

- **Sink** (où le dégât a lieu) : toujours le serveur, dans la requête SQL concaténée. Ça ne
  change jamais — SQL ne s'exécute jamais dans le navigateur.
- **Source** (où la valeur dangereuse apparaît en premier) : dans une injection SQL « serveur »
  classique, c'est un paramètre de requête HTTP lu côté serveur (`req.query`, `req.body`). Dans
  une injection SQL **basée sur le DOM**, c'est une valeur **lue par du JavaScript exécuté dans
  le navigateur, directement dans le document** — typiquement `location.hash` :

```js
// Côté client (profile.html)
const raw = decodeURIComponent(location.hash.replace(/^#id=/, ''));
fetch(`/api/profile?id=${encodeURIComponent(raw)}`);
```

Deux détails changent tout :

1. **`location.hash` (tout ce qui suit `#` dans l'URL) n'est jamais envoyé au serveur par le
   navigateur lors d'une navigation normale.** Ce n'est que lorsque ce JS lit le hash et le
   transmet lui-même via `fetch` qu'une requête HTTP contenant la charge est générée — et cette
   requête HTTP-là ressemble à n'importe quel appel API légitime fait depuis cette page.
2. Conséquence directe : **un reverse proxy, un WAF, ou une inspection côté serveur du log d'accès
   de la requête de page initiale (`GET /profile.html`) ne verra jamais la charge**. Elle
   n'existe, sous forme de requête HTTP observable, qu'au moment du `fetch` déclenché par le code
   client — généré par le navigateur de la victime, pas par l'attaquant directement.

### Conséquence sur le vecteur d'attaque : un simple lien suffit

Comme la charge vit dans l'URL, elle est transportable comme texte brut :

```
https://exemple.com/profile.html#id=3 -- 
```

Un attaquant envoie ce lien à une victime **déjà connectée**. Elle clique → son navigateur exécute
le JS de la page → ce JS lit le hash → appelle l'API avec la charge → le serveur exécute la requête
**avec la session (et les droits) de la victime**. L'attaquant n'a jamais eu besoin d'accéder au
compte de la victime ni d'envoyer lui-même une requête au serveur : il a juste eu besoin qu'elle
clique. C'est structurellement proche d'un CSRF, mais en lecture, et appliqué à une injection SQL
plutôt qu'à une action d'écriture.

## 3. Les familles de techniques (pour situer ce qu'on peut faire une fois l'injection confirmée)

| Technique | Ce qu'on fait | Ce qu'on observe |
|---|---|---|
| **Commentaire SQL** (`-- `, `/* */`) | Tronquer la requête après le point d'injection | Un filtre (souvent d'autorisation) disparaît du résultat |
| **UNION-based** | Ajouter `UNION SELECT ... FROM autre_table` | Des lignes d'une table jamais censée être exposée apparaissent dans la réponse — il faut faire correspondre le nombre et le type de colonnes |
| **Blind booléen** | Ajouter une condition (`AND 1=1` / `AND 1=2`, ou une sous-requête `SUBSTR(...) = 'x'`) | Aucune donnée affichée directement ; seul le nombre de lignes (0 ou plus) varie — on reconstruit un secret caractère par caractère |
| **Blind temporel** | Ajouter un délai conditionnel (`SLEEP()` ou équivalent) | Le temps de réponse varie selon que la condition est vraie ou fausse — utile quand même le nombre de lignes ne varie pas |
| **Error-based** | Provoquer une erreur SQL qui fuite dans le message renvoyé au client | Le message d'erreur lui-même révèle le schéma ou une donnée |

Ces techniques sont indépendantes du vecteur : qu'elle vienne de `location.hash` ou d'un
`req.query` lu directement côté serveur, une fois que l'entrée atteint une requête concaténée, on
peut appliquer n'importe laquelle de ces techniques.

## 4. Ce que la démo (Atrium) a implémenté concrètement

Cinq routes volontairement vulnérables, chacune avec une version corrigée équivalente,
couvrant les deux vecteurs et trois techniques :

| Route | Source | Technique | Ce que ça contourne |
|---|---|---|---|
| `/api/profile` | `location.hash` | Commentaire SQL | Périmètre hiérarchique (`manager_id`) |
| `/api/search` | paramètre de formulaire | UNION-based | Isolation de la table `documents` (confidentiels) |
| `/api/lab/directory` | `?department=` (URL) | UNION-based, un seul champ | Idem, avec surface minimale |
| `/api/lab/project` | `location.hash` | Commentaire SQL | Appartenance à un projet (2e modèle d'autorisation) |
| `/api/lab/login-history` | `location.hash` (admin) | Blind booléen | Extraction sans aucune donnée affichée directement |

Le détail (requêtes générées, payloads, captures) est dans `docs/FICHE-TECHNIQUE.md` ; ce document
se concentre sur le *pourquoi* du mécanisme, pas sur chaque route.

## 5. Comment corriger, concrètement

### 5.1 Requêtes paramétrées — la correction qui règle la cause racine

```js
// Vulnérable
const sql = `SELECT * FROM users WHERE id = ${id}`;
// Corrigé
const sql = `SELECT * FROM users WHERE id = ?`;
db.all(sql, [Number(id)], callback);
```

Le pilote SQL envoie le texte de la requête et les valeurs **séparément** au moteur. Le plan de
requête est compilé à partir du texte fixe (`WHERE id = ?`) ; la valeur est ensuite substituée
comme donnée littérale, jamais réinterprétée comme SQL. Un `-- ` ou un `UNION SELECT` fourni en
valeur reste une chaîne de caractères inerte. C'est vrai pour n'importe quel ORM/driver
(`node-postgres`, `mysql2`, `sqlite3`, Prisma, etc.) — le principe est identique partout, seule la
syntaxe du paramètre change (`?`, `$1`, `:name`...).

### 5.2 Sortir l'autorisation du texte SQL

```js
// Vulnérable : le filtre d'autorisation est DANS le SQL concaténé
sql += ` AND (id = ${sessionUser.id} OR manager_id = ${sessionUser.id})`;

// Corrigé : requête paramétrée simple, puis vérification en code
db.all(sql, [Number(id)], (err, rows) => {
  const row = rows[0];
  const allowed = isAdmin(sessionUser) || row.id === sessionUser.id || row.manager_id === sessionUser.id;
  if (!allowed) return res.status(403).json({ error: 'Accès refusé' });
  // ...
});
```

Une fois la ligne récupérée de façon sûre, l'autorisation devient une comparaison JS ordinaire,
qui ne dépend que de `sessionUser` (dérivé de la session serveur, jamais de l'URL) et de la ligne
retournée. Plus aucune valeur côté client ne peut l'influencer.

### 5.3 Valider le format en entrée (complémentaire)

```js
if (!/^\d+$/.test(String(id))) return res.status(400).json({ error: 'id invalide' });
```

Utile en défense en profondeur (rejette la charge avant la base), mais insuffisant seul : un champ
libre (recherche par nom) ne peut pas être réduit à une regex stricte. Ne remplace jamais 5.1.

### 5.4 Ce qui NE suffit PAS

- **Échapper manuellement les apostrophes** (`replace(/'/g, "''")`) : ne protège pas un champ
  numérique non quoté (`3 -- ` n'a pas besoin d'apostrophe).
- **Liste noire de mots-clés** (bloquer `UNION`, `OR`, `--`) : contournable par casse, encodage,
  commentaires inline, et casse des entrées légitimes.
- **Masquer les messages d'erreur côté client sans corriger l'injection** : traite la fuite
  d'information (le message d'erreur SQL brut, cas distinct — CWE-209 si besoin de la référence)
  sans traiter la cause.
- **Un WAF seul** : comme vu en §2, il ne voit jamais la charge au moment de la requête de page
  initiale quand la source est `location.hash` — il faut aussi couvrir le trafic API généré côté
  client, et ça reste une défense de second rang par rapport au code applicatif.

## 6. À retenir

Le bug n'est pas « le DOM », c'est toujours la même chose : **une valeur non fiable devient du
texte SQL exécuté, au lieu de rester une donnée**. Ce qui change avec le DOM, c'est juste où cette
valeur apparaît en premier (dans le document, lue par du JS client) avant d'atteindre le serveur —
ce qui change la détection (invisible à une inspection réseau classique) et la diffusion (un
simple lien suffit, avec les droits de la victime). La correction ne change pas selon le vecteur :
requêtes paramétrées partout, et autorisation vérifiée en code, jamais dans le texte SQL.

---

*Pour le rapport académique complet (taxonomie détaillée, modèle d'autorisation, CWE) voir
`docs/RAPPORT.md` ; pour le détail route par route (payloads, requêtes générées, captures) voir
`docs/FICHE-TECHNIQUE.md`.*
