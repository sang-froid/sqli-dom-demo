# Techniques complémentaires d'exploitation

Le labo démontre déjà, **concrètement et en direct**, deux techniques :

- **in-band** sur `/api/profile` (le résultat détourné s'affiche directement dans la fiche —
  contournement du filtre d'autorisation par commentaire SQL) ;
- **UNION-based** sur `/api/search` (des lignes de la table `documents`, y compris des documents
  confidentiels, apparaissent dans les résultats de recherche — voir le `README.md`, section
  « Où se jouent les failles »).

Cette note documente, pour le rapport, les deux familles **restées théoriques** ici (blind
booléen et temporel) — sans script d'attaque générique à livrer, avec des payloads conceptuels
adaptés au schéma d'Atrium.

Référence terminologique : CWE-89 (*Improper Neutralization of Special Elements used in an SQL
Command*) pour l'injection elle-même, CWE-209 (*Generation of Error Message Containing Sensitive
Information*) pour la fuite d'un message d'erreur SQL brut — un défaut distinct, également
illustré par la route vulnérable (`err.message` renvoyé tel quel au client).

## 1. Blind booléen (boolean-based blind)

Utile quand l'application ne renvoie plus directement les données, mais que son comportement
(nombre de résultats, page affichée) change selon qu'une condition est vraie ou fausse.

Principe sur `/api/profile?id=...&mode=vulnerable` :

```
id = 1 AND 1=1   → 1 résultat (comportement normal)
id = 1 AND 1=2   → 0 résultat (condition fausse)
```

Une fois la différence confirmée, on pose des questions booléennes sur la donnée elle-même,
caractère par caractère :

```
id = 1 AND SUBSTR((SELECT password FROM users WHERE id=6),1,1) = 'a'
```

Si le nombre de résultats redevient 1, la réponse est « oui » ; sinon « non ». On recommence
pour chaque position et chaque caractère candidat — lent, mais ça fonctionne même sans aucune
donnée visible.

## 2. Temporel (time-based blind)

Quand même le nombre de résultats ne varie pas visiblement, on force un délai conditionnel et on
mesure le temps de réponse :

```
id = 1 OR (SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN 1 ELSE (SELECT COUNT(*) FROM users, users, users) END FROM users WHERE id=6) -- délai artificiel si vrai
```

(SQLite n'a pas de `SLEEP()` natif comme MySQL ; on simule un délai par un produit cartésien
coûteux, ou on documente l'équivalent MySQL `AND IF(condition, SLEEP(2), 0)` si le SGBD cible en
dispose.) Un temps de réponse nettement plus long signale « vrai ».

## 3. UNION-based — implémenté sur `/api/search`

Permet de faire apparaître dans la réponse normale des colonnes provenant d'une autre requête,
donc potentiellement d'une autre table — à condition de faire correspondre le nombre de colonnes.
Contrairement aux deux techniques ci-dessus, celle-ci est réellement câblée dans le labo : voir
`/api/search` (`routes/lab.js`) et le scénario « Partie 2 » du `README.md`.

La requête vulnérable sélectionne 5 colonnes (`id, full_name, role, department, manager_id`) ;
le payload testé fait donc correspondre 5 colonnes venant de `documents` :

```
zzz%' UNION SELECT id, title, 'Document confidentiel', 'N/A', NULL FROM documents WHERE confidential = 1 -- 
```

Les 4 documents confidentiels (grilles de salaire, rapport d'audit, tarifs clients, résultats de
pentest) s'affichent comme des « résultats collaborateurs », déguisés derrière les mêmes
colonnes — alors que la table `documents` n'a jamais été pensée pour être exposée par cette
route. Un jury peut aussi faire tâtonner le nombre de colonnes à la main (`UNION SELECT
1,2,3,4,5 -- `) pour montrer la méthode générale avant de révéler le payload final.

## Pourquoi le blind et le temporel ne sont pas scriptés ici

Un script d'automatisation générique (sondage caractère par caractère, boucle sur tous les
codes ASCII) est un outil à double usage qui dépasse le besoin pédagogique : les démonstrations
en direct des techniques in-band et UNION-based suffisent à montrer le mécanisme et sa
correction. Documenter les deux techniques aveugles ici permet de répondre à une question de
jury sur « et si l'application n'affichait rien du tout ? » sans fournir un outil d'attaque
prêt à l'emploi.

## Détection (complémentaire)

`middleware/logger.js` journalise chaque requête SQL exécutée par les routes `/api/profile` et
`/api/search` dans `logs/requests.jsonl`. `forensic/analyze-logs.js` (lancé via `npm run forensic`) relit ce journal
et signale les motifs suspects (`OR 1=1`, `UNION SELECT`, commentaires `--`, requêtes empilées
`; DROP ...`). C'est une illustration simple de la détection a posteriori, à présenter après la
démonstration d'exploitation : on manipule le labo en mode Vulnérable, puis on lance l'analyse
pour montrer que l'attaque laisse une trace exploitable.
