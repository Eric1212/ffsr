/*
 * common.c — implementation of the shared helpers.
 */

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

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

/* ---------------------------------------------------------------- log */

/* Daemon log file (NULL = stderr only).
 * Opened by log_set_file(); written before stderr, timestamped.
 * Rotation (trimmer): as soon as the file exceeds LOG_MAX_BYTES, it is
 * renamed to "<path>.old" (overwriting the previous .old) and a fresh
 * one starts — the log file is always bounded to ~2× the limit. */
#define LOG_MAX_BYTES (1024 * 1024)     /* 1 Mo before rotation */

static FILE *g_log_fp = NULL;
static char  g_log_path[512] = "";

void log_set_file(const char *path) {
  if (g_log_fp) { fclose(g_log_fp); g_log_fp = NULL; }
  g_log_path[0] = '\0';
  if (path) {
    snprintf(g_log_path, sizeof(g_log_path), "%s", path);
    g_log_fp = fopen(path, "a");
  }
}

void log_close(void) {
  if (g_log_fp) { fclose(g_log_fp); g_log_fp = NULL; }
}

static void log_rotate_if_needed(void) {
  if (!g_log_fp || !g_log_path[0]) return;
  struct stat st;
  if (fstat(fileno(g_log_fp), &st) != 0) return;
  if (st.st_size < LOG_MAX_BYTES) return;

  fclose(g_log_fp);
  char old[sizeof(g_log_path) + 4];
  snprintf(old, sizeof(old), "%s.old", g_log_path);
  /* rename silently overwrites a previous .old */
  rename(g_log_path, old);
  g_log_fp = fopen(g_log_path, "a");   /* fresh file */
  if (g_log_fp) {
    fprintf(g_log_fp, "--- rotation (previous log in %s) ---\n", old);
  }
}

static void log_write(const char *tag, const char *fmt, va_list ap) {
  if (g_log_fp) {
    va_list apf;
    va_copy(apf, ap);   /* COPY before any use: ap must stay intact */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    fprintf(g_log_fp, "%02d-%02d %02d:%02d:%02d.%03d [%s] ",
            tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
            (int)(tv.tv_usec / 1000), tag);
    vfprintf(g_log_fp, fmt, apf);
    va_end(apf);
    fputc('\n', g_log_fp);
    fflush(g_log_fp); /* crash-safe: the line is written even on kill -9 */
    log_rotate_if_needed();
  }
  fprintf(stderr, "[ffsr] %s", tag);
  vfprintf(stderr, fmt, ap);   /* ap has NEVER been consumed: intact */
  fputc('\n', stderr);
}

void log_msg(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  log_write("", fmt, ap);
  va_end(ap);
}

void log_err(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  log_write("err: ", fmt, ap);
  va_end(ap);
}

/* ------------------------------------------------------- minimal JSON */

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

int json_unescape(Buf *b, const char *s, size_t n) {
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == '\\' && i + 1 < n) {
      char nxt = s[++i];
      switch (nxt) {
        case '"':  if (buf_append(b, "\"", 1) != 0) return -1; break;
        case '\\': if (buf_append(b, "\\", 1) != 0) return -1; break;
        case 'n':  if (buf_append(b, "\n", 1) != 0) return -1; break;
        case 't':  if (buf_append(b, "\t", 1) != 0) return -1; break;
        case 'r':  if (buf_append(b, "\r", 1) != 0) return -1; break;
        case 'b':  if (buf_append(b, "\b", 1) != 0) return -1; break;
        case 'f':  if (buf_append(b, "\f", 1) != 0) return -1; break;
        default:   /* \uXXXX: kept raw (rare here) */
          if (buf_append(b, "\\", 1) != 0) return -1;
          if (buf_append(b, &nxt, 1) != 0) return -1;
      }
    } else {
      if (buf_append(b, (const char *)&c, 1) != 0) return -1;
    }
  }
  return 0;
}

JsonVal json_get(const char *doc, size_t len, const char *key,
                 const char **str, long *num) {
  size_t klen = strlen(key);
  size_t i = 0;
  /* skip whitespace and the opening brace */
  while (i < len && (doc[i] == ' ' || doc[i] == '\t' || doc[i] == '\n')) i++;
  if (i >= len || doc[i] != '{') return JSON_NOTFOUND;
  i++;
  for (;;) {
    while (i < len && (doc[i] == ' ' || doc[i] == '\t' || doc[i] == '\n'
                       || doc[i] == ',')) i++;
    if (i >= len) return JSON_NOTFOUND;
    if (doc[i] != '"') return JSON_NOTFOUND;
    i++;
    /* read the key */
    size_t ks = i;
    while (i < len && doc[i] != '"') i++;
    if (i >= len) return JSON_NOTFOUND;
    size_t ke = i;
    i++;
    /* colon */
    while (i < len && (doc[i] == ' ' || doc[i] == '\t')) i++;
    if (i >= len || doc[i] != ':') return JSON_NOTFOUND;
    i++;
    while (i < len && (doc[i] == ' ' || doc[i] == '\t')) i++;
    if (i >= len) return JSON_NOTFOUND;
    /* value: string */
    if (doc[i] == '"') {
      i++;
      size_t vs = i;
      while (i < len && doc[i] != '"') {
        if (doc[i] == '\\') i++;   /* skip the escape */
        i++;
      }
      if (i >= len) return JSON_NOTFOUND;
      if (klen == ke - ks && memcmp(doc + ks, key, klen) == 0) {
        if (str) *str = doc + vs;
        return JSON_STR;
      }
      i++; /* close the string, continue the loop */
      continue;
    }
    /* value: number (id) */
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
    /* value: nested object / array (skip without searching inside) */
    if (doc[i] == '{' || doc[i] == '[') {
      char open = doc[i], close = open == '{' ? '}' : ']';
      int depth = 0;
      while (i < len) {
        if (doc[i] == '"') {
          i++;
          while (i < len && doc[i] != '"') {
            if (doc[i] == '\\') i++;
            i++;
          }
        } else if (doc[i] == open) depth++;
        else if (doc[i] == close) {
          depth--;
          if (depth == 0) { i++; break; }
        }
        i++;
      }
      continue;
    }
    /* value: literal (null/true/false) */
    {
      size_t vs = i;
      while (i < len && doc[i] != ',' && doc[i] != '}') i++;
      size_t vl = i - vs;
      if (klen == ke - ks && memcmp(doc + ks, key, klen) == 0) {
        /* true/false → JSON_NUM (1/0) ; null → not a value */
        if ((vl == 4 && memcmp(doc + vs, "true", 4) == 0)) {
          if (num) *num = 1;
          return JSON_NUM;
        }
        if (vl == 5 && memcmp(doc + vs, "false", 5) == 0) {
          if (num) *num = 0;
          return JSON_NUM;
        }
        return JSON_NOTFOUND;
      }
      continue;
    }
  }
}

/* --------------------------------------------------------- JSON bounds */

JsonVal json_get_str_bounds(const char *doc, size_t len, const char *key,
                            size_t *start, size_t *end) {
  size_t klen = strlen(key);
  size_t i = 0;
  while (i < len && (doc[i] == ' ' || doc[i] == '\t' || doc[i] == '\n')) i++;
  if (i >= len || doc[i] != '{') return JSON_NOTFOUND;
  i++;
  for (;;) {
    while (i < len && (doc[i] == ' ' || doc[i] == '\t' || doc[i] == '\n'
                       || doc[i] == ',')) i++;
    if (i >= len || doc[i] != '"') return JSON_NOTFOUND;
    i++;
    size_t ks = i;
    while (i < len && doc[i] != '"') i++;
    if (i >= len) return JSON_NOTFOUND;
    size_t ke = i;
    i++;
    while (i < len && (doc[i] == ' ' || doc[i] == '\t')) i++;
    if (i >= len || doc[i] != ':') return JSON_NOTFOUND;
    i++;
    while (i < len && (doc[i] == ' ' || doc[i] == '\t')) i++;
    if (i >= len) return JSON_NOTFOUND;
    /* non-string value (null/literal/object/array): skip it and
     * continue — the searched key may be further in the object */
    if (doc[i] != '"') {
      if (doc[i] == '{' || doc[i] == '[') {
        char open = doc[i], close = open == '{' ? '}' : ']';
        int depth = 0;
        while (i < len) {
          if (doc[i] == '"') {
            i++;
            while (i < len && doc[i] != '"') {
              if (doc[i] == '\\') i++;
              i++;
            }
          } else if (doc[i] == open) depth++;
          else if (doc[i] == close) {
            depth--;
            if (depth == 0) { i++; break; }
          }
          i++;
        }
      } else {
        while (i < len && doc[i] != ',' && doc[i] != '}') i++;
      }
      continue;
    }
    i++;
    size_t vs = i;
    while (i < len && doc[i] != '"') {
      if (doc[i] == '\\') i++;
      i++;
    }
    if (i >= len) return JSON_NOTFOUND;
    if (klen == ke - ks && memcmp(doc + ks, key, klen) == 0) {
      if (start) *start = vs;
      if (end) *end = i;
      return JSON_STR;
    }
    i++;
    continue;
  }
}

/* Locates the value of the top-level `key` field: bounds [start,end). */
int json_value_bounds(const char *doc, size_t len, const char *key,
                      size_t *start, size_t *end) {
  size_t klen = strlen(key);
  size_t i = 0;
  while (i < len && (doc[i] == ' ' || doc[i] == '\t' || doc[i] == '\n')) i++;
  if (i >= len || doc[i] != '{') return -1;
  i++;
  for (;;) {
    while (i < len && (doc[i] == ' ' || doc[i] == '\t' || doc[i] == '\n'
                       || doc[i] == ',')) i++;
    if (i >= len || doc[i] != '"') return -1;
    i++;
    size_t ks = i;
    while (i < len && doc[i] != '"') i++;
    if (i >= len) return -1;
    size_t ke = i;
    i++;
    while (i < len && (doc[i] == ' ' || doc[i] == '\t')) i++;
    if (i >= len || doc[i] != ':') return -1;
    i++;
    while (i < len && (doc[i] == ' ' || doc[i] == '\t')) i++;
    if (i >= len) return -1;
    /* value: string, number, object, array or literal */
    size_t vs = i, ve = vs;
    if (doc[i] == '"') {
      i++;
      vs = i;
      while (i < len && doc[i] != '"') {
        if (doc[i] == '\\') i++;
        i++;
      }
      ve = i;
      i++; /* close the string */
    } else if (doc[i] == '{' || doc[i] == '[') {
      char open = doc[i], close = open == '{' ? '}' : ']';
      int depth = 0;
      while (i < len) {
        if (doc[i] == '"') {
          i++;
          while (i < len && doc[i] != '"') {
            if (doc[i] == '\\') i++;
            i++;
          }
        } else if (doc[i] == open) depth++;
        else if (doc[i] == close) {
          depth--;
          if (depth == 0) { ve = i + 1; i++; break; }
        }
        i++;
      }
      if (depth != 0) return -1;
    } else {
      while (i < len && doc[i] != ',' && doc[i] != '}') i++;
      ve = i;
    }
    if (klen == ke - ks && memcmp(doc + ks, key, klen) == 0) {
      if (start) *start = vs;
      if (end) *end = ve;
      return 1;
    }
  }
}

/* Array iterator: `pos` must start at the position after '['.
 * Returns 0 (done), 1 (element found in [start,end)), -1 (malformed). */
int json_array_next(const char *arr, size_t len, size_t *pos,
                    size_t *start, size_t *end) {
  size_t i = *pos;
  while (i < len && (arr[i] == ' ' || arr[i] == '\t' || arr[i] == '\n'
                     || arr[i] == ',')) i++;
  if (i >= len || arr[i] == ']') { *pos = i; return 0; }
  if (arr[i] != '{') return -1;
  int depth = 0;
  size_t s = i;
  while (i < len) {
    if (arr[i] == '"') {
      i++;
      while (i < len && arr[i] != '"') {
        if (arr[i] == '\\') i++;
        i++;
      }
    } else if (arr[i] == '{') depth++;
    else if (arr[i] == '}') {
      depth--;
      if (depth == 0) {
        *start = s;
        *end = i + 1;
        *pos = i + 1;
        return 1;
      }
    }
    i++;
  }
  return -1;
}

/* ------------------------------------------------------------ utils */

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