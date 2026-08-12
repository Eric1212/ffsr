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
  validées empiriquement sur le pont vivant).
- 2026-08-11 (suite) : **décision d'architecture** — binôme **ffsrd (daemon) +
  ffsr (CLI)** : voir « Architecture ffsrd ⇄ ffsr » ci-dessous. La possession
  de la session passe au daemon ; les CLI ne parlent jamais à Firefox.
  Implémentation à venir.

## Stack

- C11 + libcurl (8.21.0-2, headers multiarch présents), GCC 15.
- **Un fichier source par binaire (zéro partage — validé Éric 2026-08-11)** :
  chaque binaire duplique ce dont il a besoin (JSON, helpers), jamais de
  `common.*`. Autonomie > DRY.
- Sortie stdout machine-readable, stderr humain.
- Le pont : `ws://127.0.0.1:9222/session`, répond SANS Origin (validé).
  Les endpoints `/json/*` sont des reliquats CDP : leur 404 est NORMAL.

## Structure du repo (validée 2026-08-11)

```
ffsr/
├── CLAUDE.md               ← la spec
├── Makefile                ← make (2 binaires) ; make install (binaires,
│                               unit systemd, config, systemctl enable)
├── src/
│   ├── ffsrd.c             ← daemon COMPLET en un fichier : WS+session,
│   │                           socket serveur, chown, state, hooks systemd
│   └── ffsr.c              ← CLI COMPLET en un fichier : parsing, socket
│                               client, toutes les commandes
├── systemd/
│   └── ffsrd.service       ← unit calquée sur ram-reclaim
└── etc/
    └── ffsrd.conf          ← config exemple (9222, FFSRD_TARGET_UID=1000)
```

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

## Architecture ffsrd ⇄ ffsr (décision 2026-08-11, validée avec Éric)

Deux binaires, rôles stricts — un WebSocket ne peut jamais « appartenir à un
utilisateur », il appartient toujours à un processus (prouvé). La meilleure
approximation : un daemon dédié (PID stable, vivant comme la session
utilisateur) qui détient SOLE possession de la connexion et de la session.

```
Firefox (9222) ◄──WS unique── ffsrd (passthrough pur, détient la session)
                               │
                          socket Unix local (ffsr.sock)
                               ▲
                          ffsr (CLI) — ne touche JAMAIS Firefox directement
```

### ffsrd — le daemon passthrough

- **Simple par nature** (validé Éric) : relais pur, aucune logique métier.
  Reçoit les demandes JSON des CLI → les transfère TELLES QUELLES sur le WS ;
  route les réponses par `id` (multiplexage validé : plusieurs demandes
  simultanées dans la même session).
- Ouvre `ws://127.0.0.1:9222/session` et crée la session UNE seule fois, au
  démarrage. Il vit en silence ensuite (persistance idle prouvée : aucun
  timeout serveur).
- Seule intelligence : la VIE de la session. Jamais de mort sans rendre :
  SIGINT/SIGTERM → `session.end` → sortie propre. Crash → le CLI relance un
  ffsrd frais ; si le pont est verrouillé par un zombie (connexion morte sans
  `session.end`), c'est le redémarrage Firefox qui purge (documenté).
- **Sa complexité est dans l'installation** (validé Éric) : unit systemd
  système (calquée sur `ram-reclaim.service` de la machine de référence :
  `Type=simple`, `ExecStart=/usr/bin/ffsrd /etc/ffsrd/config`, `Restart=on-failure`
  + `RestartSec=5s`, journal, hardening, `WantedBy=multi-user.target`,
  `Environment=FFSRD_TARGET_UID=1000`). Le daemon EST root ; il agit pour
  l'utilisateur cible quand nécessaire.
- État persistant `/var/lib/ffsrd/state` maintenu par le daemon — **unique,
  système, pas par-utilisateur** (une seule session Firefox, un seul état).

### ffsr — le CLI

- Parle au socket local du daemon (demandes/réponses JSON).
- Ne connaît PAS le pont : toute la mécanique BiDi vit dans ffsrd.
- **Pas d'auto-start** : le service systemd est `enabled` dès l'installation
  (comme ram-reclaim) — le daemon tourne, point. `ffsr d …` pilote via
  systemctl.

### Contrat `ffsr d` (contrôle du daemon, validé)

| Sous-commande | Comportement |
|---|---|
| `ffsr d status` | état du daemon + de la session (ex. : `daemon: actif (pid 1234, /run/ffsrd/ffsr.sock)` + `session: <id>` ou `aucune`) — passe par systemctl/journal |
| `ffsr d start` | `systemctl start ffsrd.service` (le daemon est root, service système) ; « déjà actif » sinon ; il établit WS + session à son démarrage |
| `ffsr d stop` | arrête proprement via le service : `session.end` AVANT de mourir (règle d'or), puis quitte |
| `ffsr d restart` | `systemctl restart ffsrd.service` |

### Flux BiDi (possession par le daemon)

```
Sous le daemon : session.new → (trouver fenêtre dédiée) → actions → la
session RESTE OUVERTE — elle n'est fermée qu'au stop propre du daemon.
```

- La session est un bien unique et précieux : une seule session active max
  par navigateur ; la perdre (connexion morte sans `session.end`) = pont
  verrouillé jusqu'au redémarrage Firefox.
- `session.status` = sonde non-créatrice (validée) : `ready:true` = libre,
  `ready:false` + `"Session already started"` = occupée. À utiliser par le
  daemon au démarrage avant tout `session.new`.
- Le reste de la mécanique (fenêtre dédiée, onglets 0-9, navigation) est
  inchangé par rapport aux sections ci-dessous.

## État persistant — survie au crash (design)

But : si ffsrd meurt en plein travail (kill, crash, coupure), l'état reste
récupérable et réconciliable au prochain démarrage. Firefox est la SOURCE DE
VÉRITÉ ; le fichier d'état est un CACHE de travail.

### Emplacement

- `/var/lib/ffsrd/state` (système, daemon root — session unique, état unique ;
  jamais dans les homes des utilisateurs).

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

## Contrat CLI (fixé au fil des décisions)

| Commande | Comportement fixé |
|---|---|
| **`ffsr go <N> <url>`** | navigue l'onglet N vers url (index explicite, en premier) ; `about:blank` vide l'onglet. Matrice PLEINE : à la création de la fenêtre dédiée, les 10 onglets existent déjà (9 × `create tab` après le contexte initial) — tout `go N` fonctionne du premier coup, aucune création conditionnelle. Diagnostique : après création, les 10 lignes de `tabs` doivent être `about:blank` — sinon anomalie |
| **`ffsr tabs`** | TOUJOURS 10 lignes (0-9, jamais strippées), format `N - URL - title - Ko` ; title = valeur réelle de `document.title` (vide = `""`) ; Ko exacts sans arrondi (`about:blank` = `0.04 Ko`) ; sert de test de santé/diagnostic (remplace `ping`) |
| **`ffsr search`** | PUR liste (comme `tabs`, aucune navigation) : affiche les moteurs de recherche acceptés avec leur URL, par ORDRE DE PRÉFÉRENCE : `google` → `https://www.google.com/search?q=` ; `paulgo` → `https://paulgo.io/search?q=` ; `startpage` → `https://www.startpage.com/sp/search?query=` ; `duckduckgo` → `https://html.duckduckgo.com/html/?q=`. La navigation se fait par `go` (l'IA compose l'URL). Vérifiés : google/startpage/ddg 200 ; paulgo 200 via navigateur réel (agrégateur → plus lent, attendre le chargement complet) |
| **`ffsr search go <onglets> <requête>`** | lance la recherche <requête> EN PARALLÈLE sur plusieurs onglets, UN moteur par onglet, mapping POSITIONNEL (position 1=google, 2=paulgo, 3=startpage, 4=duckduckgo). Onglets séparés par virgules ; une POSITION VIDE (double virgule) SAUTE le moteur correspondant : `search go 0,5,8,9 Magog` → google→0, paulgo→5, startpage→8, ddg→9 ; `search go 0,,8,9 Magog` → paulgo sauté. La requête est TOUJOURS en dernier argument |
| **`ffsr screen <N> <dossier/`** | écrit TOUJOURS un fichier WebP dans le dossier donné ; nom généré : `tab<N>_<AAAA-MM-JJ>_<HHhMM>.webp` (ex. `tab0_2026-08-11_14h32.webp`) ; imprime le chemin complet du fichier écrit sur stdout |
| **`ffsr f5 <N>`** | **HARD reload TOUJOURS** : `browsingContext.reload { context, cache:"bypass", wait:"complete" }` — jamais de cache préservé (équivalent Ctrl+Shift+R). Validé sur le pont : reload bypass OK, compteur réseau repart de zéro |
| **`ffsr get <N>`** | HTML complet de l'onglet (`document.documentElement.outerHTML`) — la base. Lecture seule, rétroactif |
| **`ffsr get child <N>`** | HTML des ENFANTS/iframes (getTree → sous-contextes → leur outerHTML). Le HTML parent montre les iframes mais pas leur contenu — c'est le correctif |
| **`ffsr get txt <N>`** | TEXTE VISIBLE (`document.body.innerText`) — l'équivalent ctrl+A : tout le texte RENDU, sans balises. Lecture seule |
| **`ffsr get net <N>`** | INSTANTANÉ réseau (PAS un stream, décision 2026-08-11) : `performance.getEntriesByType('resource')` (url, type, durée) — rétroactif, validé (98 ressources sur google). Le LLM pourra demander un vrai stream network.* plus tard si besoin |
| **`ffsr get con <N>``** | STREAM console (SEUL stream de v1) : s'abonne à `log.entryAdded` (validé : émet en direct) → `f5`/reload → **imprime chaque entrée au fil de l'eau** sur stdout → s'arrête au **Ctrl+C** du client |
| ~~`ffsr close <N>`~~ | **SUPPRIMÉ** : les 10 onglets sont permanents, jamais fermés. Vider un onglet = `open about:blank [N]` (même mécanisme que toute navigation) |

## Règles d'or

- La session appartient AU DAEMON : lui seul fait `session.new` (au start)
  et `session.end` (au stop propre). Les CLI ne font JAMAIS de session.
- **`session.end` exécuté TOUJOURS avant la mort du daemon** (SIGINT/SIGTERM
  → session.end → sortie propre ; goto cleanup en erreur). JAMAIS de mort
  sans libérer la session (sinon session zombie qui bloque le pont).
- **JAMAIS de fermeture explicite de connexion (`ws.close()`)** : `session.end`
  est le SEUL geste de fin — la mort naturelle du processus ferme le socket,
  Firefox s'en charge. (Établi avec Éric, 2026-08-11.)
- **Persistance idle prouvée (2026-08-11)** : 60 s de silence total testées —
  la connexion reste ouverte et la session répond ; aucun timeout d'inactivité
  dans le code source (WebSocketTransport/httpd.js n'ont aucun idle timeout).
  L'architecture « possesseur silencieux » est donc viable sans keepalive.
- **Un zombie (connexion morte sans `session.end`) est définitif** : la session
  ne se libère jamais d'elle-même (500 essais sur 150 s — lock_timer). Seul le
  redémarrage de Firefox purifie (c'est normal et documenté). La session est un
  bien précieux : ne JAMAIS perdre sa connexion.
- **`session.status` = la SONDE (2026-08-11, validée)** : `ready:true` → pont
  libre, on peut `session.new` ; `ready:false` + `"Session already started"` →
  session existante (orpheline ou daemon étranger) → ne PAS créer, investiguer.
  Ne JAMAIS sonder avec `session.new` (ça crée ce qu'on inspecte).
- open/close appariés : chaque fenêtre créée est fermée ; l'onglet 0 est
  réinitialisé (`about:blank`), jamais fermé ; les onglets 1-9 se ferment
  individuellement sans toucher à la fenêtre.
- Sortie stdout = données brutes/JSON ; stderr = humain ; exit 0/1/2.
- Timeout global 30 s par commande (côté daemon pour les actions, côté CLI
  pour l'attente de réponse) ; loopback `127.0.0.1:9222` codé en dur.

## Installation et usage (contrat de privilèges)

- **Binaires SYSTEMWIDE** : installés dans `/usr/local/bin/` — `ffsr` (CLI)
  et `ffsrd` (daemon) — une fois, `sudo make install` (comme `curl`/`ping`).
- **Usage indifférent au privilège** : ffsr fonctionne **avec OU sans sudo**,
  comme `curl`/`ping`. Aucune exigence de préférence — l'outil est appelable
  depuis n'importe quel context (utilisateur, root, script cron, IA).
- **Tout est système, rien n'est par-utilisateur** (validé 2026-08-11) : le
  daemon est root et la session Firefox est UNIQUE → l'état est unique.
  Jamais de `~`, de `$HOME`, de `getpwuid` : aucune résolution de home —
  on ne touche pas aux homes des utilisateurs, point.
- **Socket** : `/run/ffsrd/ffsr.sock` (système).
  **Propriété du socket** : du point de vue de ffsrd, se connecter au WS =
  dialoguer avec un AUTRE PID (le bout serveur `firefox-bin` de la connexion
  9222, lisible dans `ss -tnp`) → le possesseur du WS est donc `firefox-bin`.
  Règle : ffsrd détecte l'UID de ce PID et **chown le socket sur CET
  utilisateur + groupe `sudo`**, mode 0660. Root n'a pas besoin d'être ajouté
  (le daemon root crée le socket ; root accède à tout, de toute façon).
  Machine de référence : uid 1000 (eric) + `sudo` (eric, claude). Jamais de
  dépendance à un groupe « tous les utilisateurs » (inexistant : `users` vide
  sur Debian, peuplé sur Slackware — comportement variable, refusé).
- **État** : `/var/lib/ffsrd/state` — unique, système, écrit par le daemon.
- Conséquence : la fenêtre dédiée/les onglets sont gérés par le daemon root,
  pour son unique session ; n'importe quel appelant (eric, sudo, cron, IA)
  qui parle au socket voit le MÊME état — un `ffsr d status` répond « OK »
  quel que soit l'appelant (le root n'est jamais requis pour le runtime du CLI).
- Prérequis build : `gcc`, `libcurl4-openssl-dev` (debian).