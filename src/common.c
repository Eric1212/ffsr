/*
 * common.c — implémentation des helpers partagés.
 */

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/stat.h>

/* ------------------------------------------------------------- buffers */

void buf_init(Buf *b) {
  b->data = NULL;
  b->len = 0;
  b->cap = 0;
}

int buf_reserve(Buf *b, size_t extra) {
  if (b->len + extra + 1 <= b->cap) return 0;
  size_t ncap = b->cap ? b->cap : 256;
  while (ncap < b->len + extra + 1) ncap *= 2;
  char *nd = realloc(b->data, ncap);
  if (!nd) return -1;
  b->data = nd;
  b->cap = ncap;
  return 0;
}

int buf_append(Buf *b, const char *s, size_t n) {
  if (buf_reserve(b, n) != 0) return -1;
  memcpy(b->data + b->len, s, n);
  b->len += n;
  b->data[b->len] = '\0';
  return 0;
}

int buf_puts(Buf *b, const char *s) {
  return buf_append(b, s, strlen(s));
}

int buf_printf(Buf *b, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  va_list ap2;
  va_copy(ap2, ap);
  int n = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (n < 0) { va_end(ap2); return -1; }
  if (buf_reserve(b, (size_t)n) != 0) { va_end(ap2); return -1; }
  vsnprintf(b->data + b->len, b->cap - b->len, fmt, ap2);
  va_end(ap2);
  b->len += (size_t)n;
  return 0;
}

void buf_free(Buf *b) {
  free(b->data);
  b->data = NULL;
  b->len = b->cap = 0;
}

void buf_reset(Buf *b) {
  b->len = 0;
  if (b->data) b->data[0] = '\0';
}

/* -------------------------------------------------------------- log */

void log_msg(const char *fmt, ...) {
  va_list ap;
  fprintf(stderr, "[ffsr] ");
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}

void log_err(const char *fmt, ...) {
  va_list ap;
  fprintf(stderr, "[ffsr] err: ");
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}

/* ------------------------------------------------------- JSON minimal */

int json_escape(Buf *b, const char *s, size_t n) {
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    switch (c) {
      case '"':  if (buf_puts(b, "\\\"") != 0) return -1; break;
      case '\\': if (buf_puts(b, "\\\\") != 0) return -1; break;
      case '\b': if (buf_puts(b, "\\b")  != 0) return -1; break;
      case '\f': if (buf_puts(b, "\\f")  != 0) return -1; break;
      case '\n': if (buf_puts(b, "\\n")  != 0) return -1; break;
      case '\r': if (buf_puts(b, "\\r")  != 0) return -1; break;
      case '\t': if (buf_puts(b, "\\t")  != 0) return -1; break;
      default:
        if (c < 0x20) {
          char esc[7] = {'\\','u','0','0', hex[c>>4], hex[c&15], '\0'};
          if (buf_puts(b, esc) != 0) return -1;
        } else {
          if (buf_append(b, (const char *)&c, 1) != 0) return -1;
        }
    }
  }
  return 0;
}

JsonVal json_get(const char *doc, size_t len, const char *key,
                 const char **str, long *num) {
  size_t klen = strlen(key);
  size_t i = 0;
  /* saute les blancs et l'accolade ouvrante */
  while (i < len && (doc[i] == ' ' || doc[i] == '\t' || doc[i] == '\n')) i++;
  if (i >= len || doc[i] != '{') return JSON_NOTFOUND;
  i++;
  for (;;) {
    while (i < len && (doc[i] == ' ' || doc[i] == '\t' || doc[i] == '\n'
                       || doc[i] == ',')) i++;
    if (i >= len) return JSON_NOTFOUND;
    if (doc[i] != '"') return JSON_NOTFOUND;
    i++;
    /* lire la clé */
    size_t ks = i;
    while (i < len && doc[i] != '"') i++;
    if (i >= len) return JSON_NOTFOUND;
    size_t ke = i;
    i++;
    /* deux-points */
    while (i < len && (doc[i] == ' ' || doc[i] == '\t')) i++;
    if (i >= len || doc[i] != ':') return JSON_NOTFOUND;
    i++;
    while (i < len && (doc[i] == ' ' || doc[i] == '\t')) i++;
    if (i >= len) return JSON_NOTFOUND;
    /* valeur : string */
    if (doc[i] == '"') {
      i++;
      size_t vs = i;
      while (i < len && doc[i] != '"') {
        if (doc[i] == '\\') i++;   /* saute l'échappement */
        i++;
      }
      if (i >= len) return JSON_NOTFOUND;
      if (klen == ke - ks && memcmp(doc + ks, key, klen) == 0) {
        if (str) *str = doc + vs;
        return JSON_STR;
      }
      i++; /* ferme la string, continue la boucle */
      continue;
    }
    /* valeur : nombre (id) */
    if (isdigit((unsigned char)doc[i]) || doc[i] == '-') {
      size_t vs = i;
      while (i < len && (isdigit((unsigned char)doc[i]) || doc[i] == '-')) i++;
      if (klen == ke - ks && memcmp(doc + ks, key, klen) == 0) {
        char *end = NULL;
        long v = strtol(doc + vs, &end, 10);
        if (num) *num = v;
        (void)end;
        return JSON_NUM;
      }
      continue;
    }
    return JSON_NOTFOUND;
  }
}

/* ---------------------------------------------------------- utils */

char *xstrdup(const char *s) {
  size_t n = strlen(s) + 1;
  char *p = malloc(n);
  if (p) memcpy(p, s, n);
  return p;
}

bool file_exists(const char *path) {
  struct stat st;
  return stat(path, &st) == 0;
}