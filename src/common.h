/*
 * common.h — partagé par ffsrd et ffsr :
 *   buffers, JSON minimal (encode/décode), log, exit codes.
 * Zéro dépendance au-delà de libc.
 */

#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdbool.h>

/* ---------------------------------------------------------------- exit */

#define EXIT_OK 0      /* stdout = données brutes/JSON */
#define EXIT_ERR 1     /* erreur opérationnelle (stderr humain) */
#define EXIT_BADARGS 2 /* usage / arguments invalides */
#define EXIT_SIGINT 130 /* Ctrl+C (128 + SIGINT), règle d'or */

/* ------------------------------------------------------------- buffers */

typedef struct {
  char *data;
  size_t len;   /* octets utilisés */
  size_t cap;   /* capacité allouée */
} Buf;

void   buf_init(Buf *b);
int    buf_reserve(Buf *b, size_t extra);      /* 0 ou -1 */
int    buf_append(Buf *b, const char *s, size_t n);
int    buf_puts(Buf *b, const char *s);
int    buf_printf(Buf *b, const char *fmt, ...);  /* printf-style dans b */
void   buf_free(Buf *b);
void   buf_reset(Buf *b);

/* -------------------------------------------------------------- log */

void  log_msg(const char *fmt, ...);         /* stderr, préfixe [ffsr] */
void  log_err(const char *fmt, ...);         /* stderr, préfixe [ffsr] err: */
void  log_set_file(const char *path);        /* daemon : fichier + stderr, rotation 1 Mo */
void  log_close(void);                       /* ferme le fichier de log */

/* ------------------------------------------------------- JSON minimal */

/* Écrit une string JSON (échappé) dans b. Retourne 0 ou -1. */
int   json_escape(Buf *b, const char *s, size_t n);

/* Copie s (longueur n) dans b en DÉSÉCHAPPANT les séquences JSON
 * (\" → ", \\ → \, \n → LF, …). Utilisé pour re-parser une string JSON
 * qui a elle-même été échappée dans une valeur (script.evaluate). */
int   json_unescape(Buf *b, const char *s, size_t n);

/* Extraction brute d'un champ de premier niveau :
 *   {"id":1,"method":"x"}  →  JSON_STR  pour chaîne (mémoire interne)
 *   {"id":12,...}          →  nombre  via *num
 * Retourne 1 trouvé, 0 pas trouvé, -1 malformé.
 * NB : usage réservé au champ "id" (réécriture multiplexage ffsrd). */
typedef enum { JSON_NOTFOUND, JSON_STR, JSON_NUM } JsonVal;

JsonVal json_get(const char *doc, size_t len, const char *key,
                 const char **str, long *num);

/* Comme json_get, mais pour une string : retourne ses bornes [start,end)
 * (les délimiteurs " exclus, la fin réelle avant le " fermant). */
JsonVal json_get_str_bounds(const char *doc, size_t len, const char *key,
                            size_t *start, size_t *end);

/* Bornes [start,end) de la VALEUR du champ `key` de premier niveau.
 * Retourne 1 trouvé, 0 pas trouvé, -1 malformé. */
int json_value_bounds(const char *doc, size_t len, const char *key,
                      size_t *start, size_t *end);

/* Itérateur de tableau JSON : `pos` = position APRÈS le '[' (0 = début).
 * À chaque appel, avance au sous-objet suivant et retourne ses bornes
 * [start,end) ; retourne 0 quand le tableau est épuisé. */
int json_array_next(const char *arr, size_t len, size_t *pos,
                    size_t *start, size_t *end);

/* ---------------------------------------------------------- utils */

/* strdup-like sans POSIX : retourne malloc copié ou NULL. */
char *xstrdup(const char *s);

/* vrai si le chemin existe (stat) */
bool  file_exists(const char *path);

#endif /* COMMON_H */