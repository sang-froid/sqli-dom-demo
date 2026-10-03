# Injection SQL basee sur DOM — presentation, implementation, contre-mesures

Projet de classe (Theme 2) : demonstration executable, sans support de slides.
Toute la presentation se fait via l'interface web de l'application.

## Installation

```bash
npm install
npm start
```

Ouvrir ensuite `http://localhost:3000`.

## Organisation du depot

```
server.js             point d'entree, initialisation de la base SQLite en memoire
routes/vulnerable.js   endpoint vulnerable (concatenation de requete)
routes/secure.js       endpoint corrige (requete preparee + validation)
public/index.html      interface (5 sections : theorie, risque, demo, detection, contre-mesures)
public/app.js          logique client, dont le declencheur DOM (location.hash)
public/styles.css      identite visuelle du projet
```

## Prerequis

Node.js >= 22.13.0 (recommande : Node 24, ou `node:sqlite` est passe au
statut Release Candidate). Le projet utilise le module SQLite natif de
Node (`node:sqlite`) : aucune compilation C++ n'est necessaire, donc pas
besoin de Visual Studio Build Tools ni de Python pour l'installation.

## Resume du theme

Une injection SQL basee sur DOM se produit lorsque la donnee dangereuse
provient d'une source du navigateur (`location.hash`, `location.search`,
`document.referrer`, `postMessage`) plutot que d'une requete HTTP classique
traitee cote serveur. Reference : CWE-89 (Improper Neutralization of Special
Elements used in an SQL Command). La fuite d'un message d'erreur SQL brut
constitue un probleme distinct, CWE-209 (Information Exposure Through an
Error Message), egalement illustre dans ce projet.

## Methodologie de demonstration

1. Sondage par guillemet simple pour confirmer l'injection (erreur SQL visible).
2. Injection blind booleenne (`AND 1=1` / `AND 1=2`) pour confirmer sans
   dependre d'un message d'erreur.
3. Injection UNION-based pour exfiltrer la table `users`.
4. Declenchement via lien (hash d'URL) pour illustrer la specificite DOM :
   aucune saisie de la victime n'est necessaire.

## Contre-mesures implementees

- Requetes preparees / parametrees (defense principale).
- Validation par liste blanche des caracteres attendus.
- Hachage des mots de passe (bcrypt) — reduit l'impact d'une exfiltration
  sans remplacer la premiere contre-mesure.
- Affichage des resultats via `textContent` (jamais `innerHTML`).
- Suppression du message d'erreur SQL brut cote production (conserve ici
  a des fins pedagogiques, avec etiquette explicite).

## References

- OWASP, Top 10 Web Application Security Risks — categorie Injection.
- OWASP Testing Guide — section sur les tests d'injection SQL.
- MITRE, CWE-89 : Improper Neutralization of Special Elements used in an
  SQL Command.
- MITRE, CWE-209 : Generation of Error Message Containing Sensitive
  Information.
- CVSS v3.1 Specification Document, FIRST.org.

## Avertissement

Projet pedagogique destine a une execution locale uniquement. Ne jamais
deployer la route `/api/vulnerable` sur un environnement accessible au
reseau ou en production.
