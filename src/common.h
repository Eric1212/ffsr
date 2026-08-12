/*
 * common.h — shared by ffsrd and ffsr:
 *   buffers, minimal JSON (encode/decode), log, exit codes.
 * Zero dependency beyond libc.
 */

#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdbool.h>

/* ---------------------------------------------------------------- exit */

#define EXIT_OK 0      /* stdout = raw/JSON data */
#define EXIT_ERR 1     /* operational error (human stderr) */
#define EXIT_BADARGS 2 /* usage / invalid arguments */
#define EXIT_SIGINT 130 /* Ctrl+C (128 + SIGINT), golden rule */

/* ------------------------------------------------------------- buffers */

typedef struct {
  char *data;
  size_t len;   /* bytes used */
  size_t cap;   /* allocated capacity */
} Buf;

void   buf_init(Buf *b);
int    buf_reserve(Buf *b, size_t extra);      /* 0 or -1 */
int    buf_append(Buf *b, const char *s, size_t n);
int    buf_puts(Buf *b, const char *s);
int    buf_printf(Buf *b, const char *fmt, ...);  /* printf-style into b */
void   buf_free(Buf *b);
void   buf_reset(Buf *b);

/* ---------------------------------------------------------------- log */

void  log_msg(const char *fmt, ...);         /* stderr, [ffsr] prefix */
void  log_err(const char *fmt, ...);         /* stderr, [ffsr] err: prefix */
void  log_set_file(const char *path);        /* daemon: file + stderr, 1 Mo rotation */
void  log_close(void);                       /* closes the log file */

/* ------------------------------------------------------- minimal JSON */

/* Writes a JSON string (escaped) into b. Returns 0 or -1. */
int   json_escape(Buf *b, const char *s, size_t n);

/* Copies s (length n) into b while UNESCAPING the JSON sequences
 * (\" → ", \\ → \, \n → LF, …). Used to re-parse a JSON string that
 * was itself escaped inside a value (script.evaluate). */
int   json_unescape(Buf *b, const char *s, size_t n);

/* Raw extraction of a top-level field:
 *   {"id":1,"method":"x"}  →  JSON_STR for a string (internal memory)
 *   {"id":12,...}          →  number via *num
 * Returns 1 found, 0 not found, -1 malformed.
 * NB: use is reserved for the "id" field (ffsrd multiplexing rewrite). */
typedef enum { JSON_NOTFOUND, JSON_STR, JSON_NUM } JsonVal;

JsonVal json_get(const char *doc, size_t len, const char *key,
                 const char **str, long *num);

/* Like json_get, but for a string: returns its bounds [start,end)
 * (" delimiters excluded, actual end before the closing "). */
JsonVal json_get_str_bounds(const char *doc, size_t len, const char *key,
                            size_t *start, size_t *end);

/* Bounds [start,end) of the VALUE of the top-level `key` field.
 * Returns 1 found, 0 not found, -1 malformed. */
int json_value_bounds(const char *doc, size_t len, const char *key,
                      size_t *start, size_t *end);

/* JSON array iterator: `pos` = position AFTER the '[' (0 = start).
 * Each call advances to the next sub-object and returns its bounds
 * [start,end) ; returns 0 when the array is exhausted. */
int json_array_next(const char *arr, size_t len, size_t *pos,
                    size_t *start, size_t *end);

/* ------------------------------------------------------------ utils */

/* strdup-like without POSIX: returns a copied malloc or NULL. */
char *xstrdup(const char *s);

/* true if the path exists (stat) */
bool  file_exists(const char *path);

/* Ask the kernel for the max socket buffers (SO_RCVBUF + SO_SNDBUF,
 * clamped to the system max): heavy payloads must pass through. */
void  set_sock_buffers(int fd);

/* Write everything, retrying on partial writes. Returns 0 or -1. */
int   write_all(int fd, const char *data, size_t len);

#endif /* COMMON_H */