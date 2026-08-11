# CLAUDE.md — ffsr

## Projet

`ffsr` = **FireFox Simple Relay** — CLI en C (zéro dépendance au-delà de
libcurl) qui pilote Firefox via WebDriver BiDi sur
`ws://127.0.0.1:9222/session` (le « pont 9222 »). Objectif : remplacer les
outils de recherche externes (websearch/webfetch) par un canal local fiable
et scriptable.

## État

- 2026-08-11 : dépôt initialisé. Fonctionnement en cours de définition.

## Stack

- C11 + libcurl (8.21.0-2, headers multiarch présents), GCC 15.
- Mono-fichier + Makefile. Sortie stdout machine-readable, stderr humain.

## Conventions (à compléter)

- Sessions BiDi atomiques : session.new → action → session.end TOUJOURS
  exécuté (anti-zombie).
- open/close appariés : chaque fenêtre créée est fermée.
