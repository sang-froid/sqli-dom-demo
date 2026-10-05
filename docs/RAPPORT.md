# Injection SQL basée sur le DOM — présentation, implémentation et contre-mesures

**Projet — Sécurité des bases de données (IFRI)**
**Auteur :** Konnon Ulrich

---

## 1. Contexte

L'injection SQL (CWE-89) reste, plus de vingt ans après sa première documentation publique,
l'une des classes de vulnérabilité les plus citées des référentiels de sécurité applicative —
elle figure dans la catégorie *A03:2021 — Injection* de l'OWASP Top 10, et dans la liste CWE
Top 25 des faiblesses logicielles les plus dangereuses. La raison de cette persistance n'est pas
un manque de solution connue (la requête paramétrée existe et règle le problème depuis des
décennies dans la quasi-totalité des piles techniques), mais la façon dont l'architecture des
applications web a évolué : une part croissante de la logique applicative s'est déplacée du
serveur vers le navigateur (SPA, routage côté client, lecture de paramètres directement dans
l'URL par JavaScript), ouvrant une variante moins documentée dans les manuels classiques :
l'injection SQL **basée sur le DOM**.

Ce projet a deux objectifs :

1. **Présenter** cette variante — en quoi elle diffère réellement d'une injection SQL
   « serveur » classique, et pourquoi cette différence a des conséquences pratiques pour la
   détection et la diffusion de l'attaque (ce n'est pas une nuance purement académique) ;
2. **L'implémenter** dans une application volontairement vulnérable, construite pour l'occasion
   (« Atrium »), afin d'observer et de mesurer concrètement un fait souvent énoncé en théorie
   mais rarement montré : une injection SQL peut **annuler un contrôle d'accès applicatif
   entier**, pas seulement exposer une table voisine. Le détail de cette implémentation fait
   l'objet d'une étude de cas (section 4) et d'une fiche technique séparée
   (`docs/FICHE-TECHNIQUE.md`) ; il n'est pas le sujet du présent rapport, qui porte sur la
   faille elle-même.

---

## 2. Définition et mécanisme de la faille

### 2.1 Injection SQL — rappel

Une injection SQL se produit quand une application construit une requête par **concaténation de
texte** incluant une donnée dont l'origine n'est pas fiable, sans neutraliser les caractères qui
ont un sens syntaxique pour le moteur SQL (apostrophe, point-virgule, commentaire `--` ou `/* */`,
mots-clés `UNION`, `OR`, etc.). L'attaquant ne fournit alors pas une *donnée* mais une *extension
de la structure* de la requête : le moteur ne peut pas distinguer ce qui était prévu par le
développeur de ce que l'attaquant y a ajouté, parce que les deux arrivent dans le même texte.

### 2.2 Le modèle source → sink, et où se situe la variante « DOM »

Toute analyse de vulnérabilité par flux de données distingue :

- la **source** : l'endroit où une donnée non fiable entre dans le système ;
- le **sink** : l'endroit où cette donnée est utilisée d'une façon qui peut causer un dégât.

Dans une injection SQL **serveur classique**, la source est une donnée de requête HTTP lue
directement côté serveur (`req.query`, `req.body`, un en-tête). Dans une injection SQL **basée
sur le DOM**, la source est **lue par du code JavaScript exécuté dans le navigateur, directement
dans le document** — le cas le plus typique étant `location.hash` (le fragment d'URL après `#`),
mais aussi `location.search` relu côté client, `document.referrer`, ou `postMessage`. Ce
JavaScript transmet ensuite cette valeur — typiquement via `fetch` ou `XMLHttpRequest` — à une
API qui, côté serveur, la fait aboutir dans une requête SQL concaténée.

Le point de clarification central de ce rapport est donc :

> **« Basé sur le DOM » qualifie l'étape *source* (où et comment la valeur dangereuse apparaît :
> lue dans le document par du JavaScript client), pas l'étape *sink* (où elle cause le dégât : la
> base de données, côté serveur, exactement comme pour toute injection SQL classique).** Il ne
> s'agit pas d'une variante de SQL qui s'exécuterait « dans le navigateur » — SQL ne s'exécute
> jamais côté client dans ce schéma. C'est une injection SQL ordinaire côté serveur, dont la
> particularité est que la charge voyage d'abord par un canal que le serveur ne reçoit pas de la
> même façon qu'un paramètre de requête classique.

Chemin complet à suivre pour qualifier une injection de « basée sur le DOM » :

```
SOURCE (lue dans le document par du JS : location.hash, location.search côté client, etc.)
   → TRANSIT (JavaScript, fetch/XHR vers une API)
      → SINK (concaténation SQL côté serveur)
         → RETOUR (donnée affichée, ou simple signal présence/absence pour une variante aveugle)
```

### 2.3 Deux conséquences pratiques de cette distinction

1. **Invisibilité pour les dispositifs de filtrage réseau.** Le fragment d'URL
   (tout ce qui suit `#`) n'est **jamais envoyé au serveur par le navigateur** lors d'une
   navigation standard. Un pare-feu applicatif (WAF) ou un reverse proxy qui inspecte les
   requêtes HTTP entrantes ne voit donc jamais la charge au moment où la page est demandée : elle
   n'apparaît dans une requête HTTP que plus tard, reformulée par le JavaScript client en un
   paramètre de requête API — c'est cette seconde requête, fabriquée par le navigateur de la
   victime elle-même, qui porte réellement l'injection jusqu'au serveur. Les dispositifs de
   détection réseau conçus pour l'injection SQL « serveur » classique doivent donc couvrir ce
   trafic API généré côté client, pas seulement la requête de page initiale.

2. **Un vecteur de diffusion différent.** Comme la charge vit dans l'URL (fragment ou paramètre
   classique), elle est **partageable sous forme de lien**. Un attaquant peut faire ouvrir un lien
   piégé (`...#id=3 -- `) à une victime déjà authentifiée — par ingénierie sociale, lien
   raccourci, ou un XSS qui l'automatise sans interaction. En l'ouvrant, c'est **la session de la
   victime** qui exécute la requête côté serveur avec ses propres droits — un scénario apparenté
   à un CSRF en lecture (*confused deputy*). Ce vecteur de diffusion n'est généralement pas
   présent dans les discussions classiques de l'injection SQL, centrées sur un formulaire soumis
   directement par l'attaquant lui-même.

---

## 3. Taxonomie des techniques d'exploitation

Indépendamment du vecteur (DOM ou paramètre serveur classique), une injection SQL exploitable
suit généralement l'une de ces familles, selon ce que l'application renvoie en retour :

| Famille | Principe | Signal exploité | Condition d'usage |
|---|---|---|---|
| **In-band — commentaire SQL** | Un commentaire (`-- `, `/* */`) tronque la requête après le point d'injection, supprimant tout ce qui suivait (y compris un filtre de sécurité). | Résultat normal, mais sur un périmètre élargi ou un filtre désactivé. | Le filtre à supprimer est concaténé dans le **même** texte SQL que l'entrée. |
| **In-band — UNION-based** | `UNION SELECT` ajoute des lignes issues d'une **autre requête**, donc potentiellement d'une **autre table**, au résultat affiché. | Données supplémentaires visibles directement dans la réponse. | Le nombre de colonnes du `SELECT` d'origine doit être deviné ou connu ; les types doivent être compatibles. |
| **Blind — booléen** | Une condition ajoutée au `WHERE` change le nombre de lignes renvoyées (ou la présence/absence d'un résultat), sans qu'aucune donnée volée ne soit jamais affichée. | Présence/absence de résultat, ou différence de contenu. | Utile quand l'application ne renvoie plus directement de données exploitables, mais que son comportement varie selon une condition vraie/fausse. |
| **Blind — temporel** | Un délai conditionnel (`SLEEP()`, ou une opération coûteuse simulée si le moteur n'a pas de fonction de pause) rend le temps de réponse lui-même le signal. | Durée de la réponse HTTP. | Dernier recours quand même le comportement visible ne varie pas — plus lent, mais fonctionne en l'absence de tout signal applicatif. |
| **Error-based** | Une erreur SQL délibérément provoquée (ex. conversion de type invalide) fait fuiter, dans le message d'erreur renvoyé au client, une information sur le schéma ou les données (CWE-209). | Contenu du message d'erreur. | Nécessite que l'application renvoie les messages d'erreur du moteur SQL sans les filtrer. |

Ces familles ne sont pas mutuellement exclusives : une même surface vulnérable peut souvent être
exploitée par plusieurs d'entre elles selon ce que l'attaquant choisit d'observer. Un point
transversal, indépendant de la famille choisie : quand un filtre d'autorisation (« cet utilisateur
a-t-il le droit de voir cette ligne ? ») est exprimé dans le **même texte SQL** que l'entrée non
validée, les familles *in-band* (commentaire, UNION) ne se contentent pas d'exfiltrer une donnée —
elles peuvent **désactiver ce contrôle d'accès lui-même**, ce qui déplace la faille d'une simple
fuite de données (CWE-89) vers un contournement d'autorisation (CWE-285/CWE-639).

---

## 4. Étude de cas — implémentation dans Atrium (synthèse)

Pour observer ces mécanismes sans se limiter à la théorie, le projet a construit **Atrium**, une
application d'annuaire d'entreprise fictive avec un vrai système d'authentification (sessions,
bcrypt) et un vrai modèle d'autorisation à deux niveaux (périmètre hiérarchique sur les fiches,
cloisonnement des documents confidentiels par appartenance à un projet). Seules cinq routes de
lecture, choisies pour couvrir les deux vecteurs (DOM et paramètre d'URL classique) et les trois
techniques principales (commentaire, UNION, booléen), construisent leurs requêtes par
concaténation ; le reste de l'application (connexion, écritures, administration) utilise des
requêtes paramétrées. Ce choix de conception permet d'observer en direct la thèse posée en
section 3 : sur deux de ces cinq routes, l'injection ne se contente pas d'exfiltrer une donnée,
elle **supprime le filtre d'autorisation** qui, par ailleurs, fonctionne correctement en usage
normal.

Résumé des cinq surfaces (détail complet — requêtes générées, captures, scénario de démonstration
pas à pas — dans `docs/FICHE-TECHNIQUE.md` et `README.md`) :

| Surface | Vecteur | Technique | Ce que l'injection contourne |
|---|---|---|---|
| `/api/profile` (`profile.html#id=...`) | DOM | Commentaire SQL | Périmètre hiérarchique (`manager_id`) |
| `/api/search` (champ Nom) | Paramètre/formulaire | UNION-based | Isolation de la table `documents` (confidentiels) |
| `/api/lab/directory` (`?department=...`) | Paramètre d'URL | UNION-based, un seul champ | Idem, avec une surface d'injection minimale |
| `/api/lab/project` (`project.html#id=...`) | DOM | Commentaire SQL | Appartenance au projet (second modèle d'autorisation) |
| `/api/lab/login-history` (admin, `#user=...`) | DOM | Booléen (aveugle) | — (extraction sans affichage direct, démontre que l'absence de donnée visible ne protège pas) |

Chaque route dispose d'une implémentation **Corrigée** équivalente fonctionnellement, activable
par un sélecteur dans l'interface, pour comparer directement les deux comportements sur les mêmes
données.

---

## 5. Contre-mesures générales et pourquoi elles fonctionnent

### 5.1 Requêtes paramétrées (préparées) — la défense qui règle la cause racine

```sql
-- Vulnérable (concaténation)
SELECT ... WHERE u.id = <valeur collée dans le texte>
-- Corrigé (paramètre lié)
SELECT ... WHERE u.id = ?    -- valeur transmise séparément du texte
```

**Pourquoi ça marche :** avec une requête préparée, le pilote envoie le **texte** de la requête
et les **valeurs** séparément au moteur. Le moteur compile d'abord le plan à partir du texte fixe,
puis substitue la valeur comme une donnée littérale — jamais comme du texte SQL réinterprété. Un
commentaire ou un mot-clé SQL fourni en valeur reste une chaîne de caractères inerte : il ne peut
plus, par construction, changer la structure de la requête. C'est la seule défense qui élimine la
cause racine (section 2.1) plutôt que de traiter un symptôme, et elle s'applique identiquement que
la source soit DOM ou serveur — la correction ne dépend pas du vecteur.

### 5.2 Autorisation vérifiée en code, séparée de la requête de lecture

Quand un contrôle d'accès est en jeu, le correctif ne se limite pas à paramétrer la requête : il
faut aussi **sortir le filtre d'autorisation du texte SQL**. Concrètement, récupérer la ligne par
une requête paramétrée simple (identifiée par un entier validé), puis vérifier en code — une
comparaison JavaScript/applicative ordinaire — si l'utilisateur courant a le droit d'y accéder,
avant de la renvoyer. Cette vérification ne dépend plus que de l'identité de session (jamais de
l'URL) et de la ligne récupérée : aucune valeur fournie par le client ne peut plus l'influencer,
contrairement à un filtre écrit dans la clause `WHERE` elle-même.

### 5.3 Validation de format en entrée — complémentaire, pas suffisante seule

Restreindre un champ à un format strict (un entier pour un identifiant, une regex pour un nom
d'utilisateur) élimine toute possibilité d'y glisser un caractère de contrôle SQL, et rejette la
charge **avant** qu'elle n'atteigne la base — une défense en profondeur utile. Mais elle ne
protège que les champs à format contraint ; un champ libre (recherche par nom, par exemple) ne
peut pas être réduit à une regex stricte sans casser la fonctionnalité. Elle vient donc **en plus
de** la paramétrisation, jamais à sa place.

### 5.4 Pourquoi certaines protections usuelles ne suffisent pas

- **Échappement manuel des caractères spéciaux** (ex. doubler les apostrophes) : traite un
  symptôme ponctuel (un caractère de citation), mais un identifiant numérique non quoté comme
  `3 -- ` n'a même pas besoin d'apostrophe pour injecter un commentaire. Ce n'est pas une solution
  générale, contrairement à la paramétrisation.
- **Liste noire de mots-clés** (bloquer `UNION`, `--`, `OR`) : contournable (casse, encodage,
  commentaires inline, formulations équivalentes) et casse des entrées légitimes contenant ces
  mots.
- **Masquage du message d'erreur côté client sans empêcher l'erreur** : traite la fuite
  d'information (CWE-209) sans traiter la cause ; un message générique côté client doit
  s'accompagner d'une vraie correction de l'injection, pas la remplacer.
- **Filtrage réseau (WAF) seul, côté serveur :** comme établi en section 2.3, un WAF ne voit
  jamais la charge au moment de la requête de page initiale quand la source est `location.hash` ;
  il doit être positionné pour inspecter le trafic API généré côté client, et reste de toute façon
  une défense de second rang par rapport à la paramétrisation du code applicatif.

### 5.5 Synthèse

| Cause racine | Contre-mesure |
|---|---|
| L'entrée devient du texte SQL réinterprété | Requête paramétrée |
| Un contrôle d'accès est écrit dans ce texte SQL | Autorisation vérifiée en code, après lecture paramétrée |
| Une valeur mal formée atteint quand même la base | Validation de format stricte en amont |
| Un message d'erreur SQL expose le schéma | Erreur générique côté client, détail en log serveur uniquement |
| Détection réseau inefficace sur une source DOM | Couvrir le trafic API généré côté client, pas seulement la requête de page |

---

## 6. Conclusion

L'injection SQL basée sur le DOM n'est pas une classe de vulnérabilité fondamentalement
différente de l'injection SQL classique : le mécanisme qui cause le dégât — une entrée non
validée devenant une partie de la structure SQL exécutée côté serveur — est identique. Ce qui
change est l'étape *source* : la donnée dangereuse est d'abord lue dans le document par du
JavaScript exécuté dans le navigateur, avant d'être transmise à l'API. Cette différence a deux
implications concrètes et sous-estimées : elle rend l'attaque invisible aux dispositifs de
filtrage réseau positionnés uniquement sur les requêtes de page, et elle ouvre un vecteur de
diffusion par simple lien, apparenté à un CSRF en lecture.

L'implémentation réalisée dans Atrium confirme par ailleurs un point souvent énoncé en théorie
sans être montré : quand un contrôle d'accès applicatif est exprimé dans le même texte SQL que
l'entrée non validée, une injection ne se limite pas à exposer une donnée supplémentaire — elle
peut supprimer ce contrôle d'accès dans son intégralité. La correction, dans tous les cas, suit le
même principe : sortir la logique sensible (structure de la requête, décision d'autorisation) du
texte manipulable par l'entrée, qu'elle provienne du DOM ou d'un paramètre serveur classique.

---

## 7. CWE et références

| Identifiant | Intitulé | Pertinence |
|---|---|---|
| **CWE-89** | *Improper Neutralization of Special Elements used in an SQL Command* (SQL Injection) | Cause racine de la faille étudiée. |
| **CWE-285** | *Improper Authorization* | Un contrôle d'accès existe mais est mal placé (dans le texte SQL concaténé). |
| **CWE-639** | *Authorization Bypass Through User-Controlled Key* (IDOR) | Un identifiant fourni par le client contrôle directement la ligne atteinte, sans vérification indépendante. |
| **CWE-209** | *Generation of Error Message Containing Sensitive Information* | Fuite d'un message d'erreur SQL brut vers le client. |
| **OWASP A03:2021** | *Injection* | Catégorie générale du Top 10 couvrant l'injection SQL. |

**Références externes :**
- MITRE, CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- MITRE, CWE-285 — <https://cwe.mitre.org/data/definitions/285.html>
- MITRE, CWE-639 — <https://cwe.mitre.org/data/definitions/639.html>
- MITRE, CWE-209 — <https://cwe.mitre.org/data/definitions/209.html>
- OWASP, *SQL Injection* — <https://owasp.org/www-community/attacks/SQL_Injection>
- OWASP, *DOM Based XSS* (pour la notion de source/sink DOM, transposée ici au SQL) — <https://owasp.org/www-community/attacks/DOM_Based_XSS>
- OWASP Cheat Sheet Series, *SQL Injection Prevention* — <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>
- OWASP Top 10:2021, *A03:2021 — Injection* — <https://owasp.org/Top10/A03_2021-Injection/>

---

*Annexes : le détail complet de l'implémentation (modèle d'autorisation d'Atrium, les 5
scénarios d'exploitation avec requêtes SQL générées et captures, scénario de démonstration pas à
pas) se trouve dans `README.md` et `docs/FICHE-TECHNIQUE.md`. Ce rapport porte sur la faille en
tant que sujet de sécurité ; Atrium n'y apparaît que comme preuve de concept.*
