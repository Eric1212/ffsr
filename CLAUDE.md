# CLAUDE.md — ffsr

## Projet

`ffsr` = **FireFox Simple Relay** — CLI en C (zéro dépendance au-delà de
libcurl) qui rend **simple l'accès au remote-debugging-port de Firefox
153.0.3** (WebDriver BiDi sur `ws://127.0.0.1:9222/session`, le « pont 9222 »).

**Objectif** : qu'un utilisateur — IA ou humain — puisse facilement gérer
Firefox à distance **sans tester 12 configurations** : ffsr encapsule le
flux BiDi complet (session, fenêtre dédiée, onglets), les pièges connus
(sessions zombies, IDs volatils, endpoints CDP 404) et expose une interface
simple et fiable. L'usage typique est de sonder des pages (scrap léger,
vérifications), en contrôlant une fenêtre Firefox dédiée, visible et unique.

## État

- 2026-08-11 : dépôt initialisé. Fonctionnement défini (structure + mécanique
  validées empiriquement sur le pont vivant). Implémentation à venir.

## Stack

- C11 + libcurl (8.21.0-2, headers multiarch présents), GCC 15.
- Mono-fichier + Makefile. Sortie stdout machine-readable, stderr humain.
- Le pont : `ws://127.0.0.1:9222/session`, répond SANS Origin (validé).
  Les endpoints `/json/*` sont des reliquats CDP : leur 404 est NORMAL.

## Structure ffsr ⇄ Firefox (validée 2026-08-11, vivante)

### Fenêtre dédiée — prérequis de fiabilité n°1

- ffsr entretient **UNE fenêtre Firefox visible dédiée** (`create type=window`).
- Tous les onglets vivent **DANS cette fenêtre unique**, jamais ailleurs.
- **La fenêtre dédiée = la fenêtre active au moment de l'action** (`active=true`
  dans `browser.getClientWindows`). Ne JAMAIS se fier à un ID mémorisé :
  Firefox rotate les IDs de fenêtres (observé 2026-08-11 : `90a10980` →
  `e141ddd0`). Recherche dynamique à chaque commande.
- Firefox place les `create type=tab` dans la fenêtre active du moment =
  la fenêtre dédiée (validé : 2 onglets consécutifs tombés dans la même
  fenêtre prise en `active=true`).

### Convention d'onglets (0-9 — gestion directe dès le départ)

**Décision 2026-08-11** : pas de phase v1 limitée à l'onglet 0. La mécanique
complète 0-9 étant validée empiriquement (facilité déconcertante), ffsr gère
**les 10 onglets d'emblée**.

| Onglet | Origine | Usage |
|---|---|---|
| **0** | contexte né AVEC la fenêtre (`create type=window` retourne déjà `context`) | on **navigue dedans** (`browsingContext.navigate`), on ne le crée jamais ; sa fermeture = `navigate about:blank` |
| **1-9** | créés par `create type=tab` successifs (tombent tous dans la fenêtre dédiée — validé) | créés, navigués, fermés par `browsingContext.close` |

- Fermer un onglet 1-9 ≠ fermer la fenêtre ; la fenêtre survit aux commandes.
- Le « onglet 0 » existe même si jamais utilisé : première navigation = l'onglet
  affiché à la création (validé : l'onglet `about:blank` initial a reçu google.ca).
- Mapping index → contextId maintenu dans l'état persistant (voir plus bas).

### Flux BiDi par commande (session atomique)

```
session.new → (trouver fenêtre dédiée) → action(s) → session.end (TOUJOURS)
```

- `session.end` exécuté même en erreur (goto cleanup) — anti-zombie, une
  session active max par navigateur ; sans lui le pont refuse (`session not
  created` / « Maximum sessions »).
- Navigation : `browsingContext.navigate {context, url, wait:"complete"}`.

## État persistant — survie au crash (design)

But : si ffsr meurt en plein travail (kill, crash, coupure), l'état reste
récupérable et réconciliable au prochain appel. Firefox est la SOURCE DE
VÉRITÉ ; le fichier d'état est un CACHE de travail.

### Emplacement

- `~/.local/state/ffsr/state` (XDG state dir) — répertoire créé par ffsr.

### Contenu (format texte simple, une clé par ligne)

```
window=<id provisoire, hint seulement>
tab0=<contextId>  ...  tab9=<contextId>
nbtabs=<nombre d'onglets actifs>
```

- `window` = HINT (l'ID peut avoir rotaté) ; la vraie fenêtre est retrouvée
  par `active=true` au prochain appel.
- `tabN` = contextId connu ; `nbtabs` = bornes 0-9.

### Écriture (write-through atomique)

- Réécriture du fichier APRÈS chaque mutation d'état (création, navigation
  d'onglet 0, fermeture, réinitialisation).
- Atomique : écriture dans `state.tmp` puis `rename()` → pas de fichier
  corrompu si crash en plein écriture.

### Réconciliation au démarrage (anti-crash)

1. Lire `state` (s'il existe).
2. `browsingContext.getTree` → vérifier quels `tabN` vivent encore.
3. Onglets morts : purgés de l'état ; l'index reste libre.
4. Onglets vivants : conservés, re-liés à la fenêtre dédiée.
5. Si l'onglet 0 n'existe plus (fenêtre fermée manuellement) : recréer
   fenêtre dédiée + état vierge au prochain besoin.
6. Si ffsr a crashé entre `create window` et l'écriture du state : fenêtre
   orpheline ignorée ; un `create` frais repart de zéro proprement.

## Règles d'or

- Sessions BiDi atomiques : `session.new` → action → `session.end` TOUJOURS exécuté.
- open/close appariés : chaque fenêtre créée est fermée ; l'onglet 0 est
  réinitialisé (`about:blank`), jamais fermé ; les onglets 1-9 se ferment
  individuellement sans toucher à la fenêtre.
- Sortie stdout = données brutes/JSON ; stderr = humain ; exit 0/1/2.
- Timeout global 30 s par commande ; loopback `127.0.0.1:9222` codé en dur.

## Installation et usage (contrat de privilèges)

- **Binaire SYSTEMWIDE** : installé dans `/usr/local/bin/ffsr` (une fois,
  `sudo make install` — comme `curl` ou `ping`).
- **Usage indifférent au privilège** : ffsr fonctionne **avec OU sans sudo**,
  comme `curl`/`ping`. Aucune exigence de préférence — l'outil est appelable
  depuis n'importe quel context (utilisateur, root, script cron, IA).
- **État par-utilisateur** : `~/.local/state/ffsr/state` est résolu **selon
  l'utilisateur qui invoque** (root → `/root/.local/...`, eric →
  `/home/eric/.local/...`). Chaque context a son propre état, c'est volontaire
  et sain : ffsr ne mélange jamais les états entre utilisateurs.
- Conséquence : la fenêtre dédiée/les onglets pilotés par un contexte donné
  appartiennent à ce context ; un `ffsr ping` répond « OK » quel que soit
  l'appelant (le root n'est jamais requis pour le runtime).
- Prérequis build : `gcc`, `libcurl4-openssl-dev` (debian).