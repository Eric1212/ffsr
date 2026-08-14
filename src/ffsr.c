/*
 * ffsr — the CLI that speaks BiDi to Firefox THROUGH the ffsrd tunnel.
 *
 * ffsr does not know the 9222 bridge: it connects to /run/ffsrd/ffsr.sock,
 * sends its raw JSON BiDi frame (as if it were on 9222), ffsrd rewrites
 * the id and relays it to Firefox; the response comes back here with the
 * original id restored, and ffsr prints it as-is on stdout.
 *
 * Commands: tabs (list the dedicated window), go (navigate a tab),
 * search / search go (search engines), f5 (hard reload),
 * d (systemctl wrapper), and raw BiDi frame pass-through.
 */

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <dirent.h>

#define SOCK_PATH       "/run/ffsrd/ffsr.sock"
#define WINDOW_SOCK     "/run/ffsrd/window.sock"

/* get-file channel (2026-08-12): the daemon directs the downloads
 * from Firefox to this directory; the CLI reads the files, serves them on
 * then purges them. */
#define STAGING_DIR     "/tmp/ffsr"
#define FALLBACK_TO     60   /* max patience for staging poll (seconds) */
#define SERIALIZE_TO    10   /* Direct serialization attempt timeout */

/* ---------------------------------------------- socket to the tunnel */

static int tunnel_connect(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return -1;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SOCK_PATH);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
  }
  set_sock_buffers(fd);   /* heavy responses must pass through */
  return fd;
}

/* ------------------------------------------------ frame + response */

/* read until EOF with a time cap: the CLI NEVER hangs, even if the
 * daemon stays silent (decision 2026-08-12). */
static int read_until_eof(int fd, Buf *out, int timeout_s) {
  struct timeval tv;
  fd_set rfds;
  char tmp[8192];
  for (;;) {
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    tv.tv_sec = timeout_s;
    tv.tv_usec = 0;
    int r = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (r <= 0) return -1;          /* timeout: give up gracefully */
    ssize_t n = read(fd, tmp, sizeof(tmp));
    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (n == 0) return 0;           /* EOF: full response */
    if (buf_append(out, tmp, (size_t)n) != 0) return -1;
  }
}

/* One full tunnel call: connect, send the frame, read until EOF. */
static int cli_call_t(const char *trame, Buf *out, int timeout_s) {
  int fd = tunnel_connect();
  if (fd < 0) {
    log_err("ffsrd unreachable (%s) — is it running? (ffsr d status)",
            strerror(errno));
    return EXIT_ERR;
  }
  if (write_all(fd, trame, strlen(trame)) != 0) {
    log_err("tunnel write: %s", strerror(errno));
    close(fd);
    return EXIT_ERR;
  }
  buf_init(out);
  if (read_until_eof(fd, out, timeout_s) != 0) {
    log_err("ffsrd silent (timeout %d s) — incomplete response?", timeout_s);
    close(fd);
    buf_free(out);
    return EXIT_ERR;
  }
  close(fd);
  return EXIT_OK;
}

static int cli_call(const char *trame, Buf *out) {
  return cli_call_t(trame, out, 10);
}

/* Send the frame and print the response on stdout as-is. */
static int send_trame(const char *trame, size_t len) {
  Buf out;
  if (cli_call(trame, &out) != EXIT_OK) return EXIT_ERR;
  if (out.len > 0) fwrite(out.data, 1, out.len, stdout);
  buf_free(&out);
  (void)len;
  return EXIT_OK;
}

/* ----------------------------------------------------------- dispatch */

/* THE dedicated window hash — FIRST read of every command (decision
 * 2026-08-12): window.sock, served by ffsrd (fresh resolution via
 * getTree + state). The CLI never guesses the window. */
static int window_hash(char *out, size_t sz) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) { log_err("socket: %s", strerror(errno)); return -1; }
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", WINDOW_SOCK);
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    log_err("window.sock unreachable (%s) — ffsrd running? (ffsr d status)",
            strerror(errno));
    close(fd);
    return -1;
  }
  Buf b;
  buf_init(&b);
  if (read_until_eof(fd, &b, 10) != 0) {
    log_err("window.sock silent (timeout 10 s) — ffsrd busy?");
    close(fd);
    buf_free(&b);
    return -1;
  }
  close(fd);
  /* strip the trailing '\n' if any */
  if (b.len > 0 && b.data[b.len - 1] == '\n') b.len--;
  if (b.len == 0) {
    log_err("window.sock: empty response — dedicated window missing?");
    buf_free(&b);
    return -1;
  }
  size_t l = b.len < sz - 1 ? b.len : sz - 1;
  memcpy(out, b.data, l);
  out[l] = '\0';
  buf_free(&b);
  return 0;
}

/* Extract the "value" string of a script.evaluate response:
 * {"type":"success","id":N,"result":{"realm":…,"result":{"type":"string",
 * "value":"…"}}} — returns the ABSOLUTE bounds [*start,*end) in doc. */
static int get_script_value(const char *doc, size_t len,
                            size_t *start, size_t *end) {
  size_t rs = 0, re = 0, rs2 = 0, re2 = 0, vs = 0, ve = 0;
  if (json_value_bounds(doc, len, "result", &rs, &re) != 1) return -1;
  if (json_value_bounds(doc + rs, re - rs, "result", &rs2, &re2) != 1) return -1;
  if (json_get_str_bounds(doc + rs + rs2, re2 - rs2, "value", &vs, &ve)
      != JSON_STR) return -1;
  *start = rs + rs2 + vs;   /* absolute bounds inside doc */
  *end   = rs + rs2 + ve;
  return 0;
}

/* THE shared foundation (tabs, go, and future commands): the dedicated
 * window hash via window.sock, then getTree filtered on that hash →
 * the ORDERED tab list of the dedicated window (contextIds + urls, in
 * getTree order). Returns the tab count (0 = dedicated window not
 * found). cw = hash read, for potential log lines. */
static int resolve_dedicated(char cw[64], char ctxs[64][64],
                             char urls[64][2048]) {
  if (window_hash(cw, 64) != 0) return 0;

  Buf out;
  if (cli_call("{\"id\":2,\"method\":\"browsingContext.getTree\","
               "\"params\":{\"maxDepth\":0}}", &out) != EXIT_OK) return 0;
  char cws[64][64];
  int n = 0;
  {
    size_t rs = 0, re = 0, cs = 0, ce = 0;
    if (json_value_bounds(out.data, out.len, "result", &rs, &re) != 1
        || json_value_bounds(out.data + rs, re - rs, "contexts", &cs, &ce) != 1) {
      log_err("getTree: unexpected response");
      buf_free(&out);
      return 0;
    }
    const char *arr = out.data + rs + cs;
    size_t pos = 1, s = 0, e = 0;
    while (n < 64 && json_array_next(arr, ce - cs, &pos, &s, &e) > 0) {
      size_t vs = 0, ve = 0;
      if (json_get_str_bounds(arr + s, e - s, "context", &vs, &ve) != JSON_STR)
        continue;
      size_t cl = ve - vs < sizeof(ctxs[n]) - 1 ? ve - vs
                                                : sizeof(ctxs[n]) - 1;
      memcpy(ctxs[n], arr + s + vs, cl); ctxs[n][cl] = '\0';
      size_t us = 0, ue = 0;
      urls[n][0] = '\0';
      if (json_get_str_bounds(arr + s, e - s, "url", &us, &ue) == JSON_STR) {
        size_t ul = ue - us < sizeof(urls[n]) - 1 ? ue - us
                                                  : sizeof(urls[n]) - 1;
        memcpy(urls[n], arr + s + us, ul); urls[n][ul] = '\0';
      }
      cws[n][0] = '\0';
      if (json_get_str_bounds(arr + s, e - s, "clientWindow", &vs, &ve)
          == JSON_STR) {
        size_t wl = ve - vs < sizeof(cws[n]) - 1 ? ve - vs
                                                 : sizeof(cws[n]) - 1;
        memcpy(cws[n], arr + s + vs, wl); cws[n][wl] = '\0';
      }
      n++;
    }
  }
  buf_free(&out);

  /* the dedicated window tabs, in getTree order (sequence) */
  int idx = 0;
  for (int i = 0; i < n && idx < 64; i++) {
    if (!cws[i][0] || strcmp(cws[i], cw) != 0) continue;
    if (idx != i) {  /* compact towards the front */
      memcpy(ctxs[idx], ctxs[i], sizeof(ctxs[idx]));
      memcpy(urls[idx], urls[i], sizeof(urls[idx]));
    }
    idx++;
  }
  return idx;
}

/* ffsr tabs — the dedicated window only, 10 lines in order,
 * format spec: N - URL - title - Ko. */
static int cmd_tabs(void) {
  char cw[64];
  char ctxs[64][64];
  char urls[64][2048];
  int count = resolve_dedicated(cw, ctxs, urls);
  if (count == 0) {
    printf("(no tabs in the dedicated window)\n");
    return EXIT_ERR;
  }

  Buf out;
  int idx = 0;
  for (int i = 0; i < count; i++) {
    char title[512] = "";
    double ko = 0.0;
    char trame[512];
    snprintf(trame, sizeof(trame),
             "{\"id\":3,\"method\":\"script.evaluate\",\"params\":{"
             "\"expression\":\"JSON.stringify({t:document.title,"
             "l:document.documentElement.outerHTML.length})\","
             "\"target\":{\"context\":\"%.63s\"},"
             "\"awaitPromise\":false,\"resultOwnership\":\"none\"}}",
             ctxs[i]);
    if (cli_call(trame, &out) == EXIT_OK) {
      size_t vs = 0, ve = 0;
      if (get_script_value(out.data, out.len, &vs, &ve) == 0) {
        Buf clean;
        buf_init(&clean);
        if (json_unescape(&clean, out.data + vs, ve - vs) == 0 && clean.len) {
          size_t ts = 0, te = 0;
          long l = 0;
          if (json_get_str_bounds(clean.data, clean.len, "t", &ts, &te)
              == JSON_STR) {
            size_t tl = te - ts < sizeof(title) - 1 ? te - ts
                                                    : sizeof(title) - 1;
            memcpy(title, clean.data + ts, tl);
            title[tl] = '\0';
          }
          if (json_get(clean.data, clean.len, "l", NULL, &l) == JSON_NUM)
            ko = (double)l / 1024.0;
        }
        buf_free(&clean);
      }
      buf_free(&out);
    }
    printf("%d - %s - %s - %.2f Ko\n", idx, urls[i], title, ko);
    idx++;
  }
  return EXIT_OK;
}

/* Detect a protocol scheme at the start of the URL ([a-z][a-z0-9+.-]*:).
 * "example.org" → no ; "https://…" / "about:blank" / "data:…" → yes. */
static int has_scheme(const char *url) {
  if (!((url[0] >= 'a' && url[0] <= 'z') ||
        (url[0] >= 'A' && url[0] <= 'Z')))
    return 0;
  for (const char *p = url + 1; *p; p++) {
    if (*p == ':') return 1;
    if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
          (*p >= '0' && *p <= '9') || *p == '+' || *p == '-' || *p == '.'))
      return 0;
  }
  return 0;
}

/* percent-encode of a query (C++ → C%2B%2B, spaces → %20). */
static void url_encode(const char *in, char *out, size_t sz) {
  static const char *hex = "0123456789ABCDEF";
  size_t o = 0;
  for (const char *p = in; *p && o + 3 < sz; p++) {
    unsigned char c = (unsigned char)*p;
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~') {
      out[o++] = (char)c;
    } else {
      out[o++] = '%';
      out[o++] = hex[c >> 4];
      out[o++] = hex[c & 15];
    }
  }
  out[o] = '\0';
}

/* The core of every navigation: escape the URL for JSON, send
 * browsingContext.navigate, silent on success, errors to stderr. */
static int navigate_ctx(const char *ctx, const char *url, const char *wait,
                        int timeout_s) {
  char eurl[4096];
  size_t o = 0;
  for (const char *p = url; *p && o + 6 < sizeof(eurl); p++) {
    switch (*p) {
      case '"':  eurl[o++] = '\\'; eurl[o++] = '"';  break;
      case '\\': eurl[o++] = '\\'; eurl[o++] = '\\'; break;
      case '\n': eurl[o++] = '\\'; eurl[o++] = 'n';  break;
      case '\r': eurl[o++] = '\\'; eurl[o++] = 'r';  break;
      default:   eurl[o++] = *p;                     break;
    }
  }
  eurl[o] = '\0';

  char trame[5600];
  snprintf(trame, sizeof(trame),
           "{\"id\":3,\"method\":\"browsingContext.navigate\",\"params\":{"
           "\"context\":\"%.63s\",\"url\":\"%s\",\"wait\":\"%s\"}}",
           ctx, eurl, wait);

  Buf out;
  buf_init(&out);
  if (cli_call_t(trame, &out, timeout_s) != EXIT_OK) {
    buf_free(&out);
    return EXIT_ERR;
  }
  int err = strstr(out.data, "\"type\":\"error\"") != NULL;
  if (err) log_err("navigate: %.*s", (int)(out.len < 400 ? out.len : 400),
                   out.data);
  buf_free(&out);
  return err ? EXIT_ERR : EXIT_OK;
}

/* ffsr go <N> <url> w — navigate tab N of the dedicated window.
 * Without 'w': wait:none (immediate response, prompt back right away).
 * With 'w': wait:interactive — the prompt comes back only once the DOM
 * is ready (the shell "hangs" during the load).
 * NO output on success: the prompt coming back IS the confirmation
 * (decision 2026-08-12); errors go to stderr only. */
static int cmd_go(int n, const char *url, int want_wait) {
  char cw[64];
  char ctxs[64][64];
  char urls[64][2048];
  int count = resolve_dedicated(cw, ctxs, urls);
  if (count == 0) {
    log_err("dedicated window not found — no tabs?");
    return EXIT_ERR;
  }
  if (n >= count) {
    log_err("tab %d out of range: dedicated window has %d tab(s)", n, count);
    return EXIT_BADARGS;
  }

  /* Decision 2026-08-12: missing protocol scheme → https:// prefixed;
   * present (http, file, about, data…) → input taken as-is. */
  char fixed[4120];
  const char *target = url;
  if (!has_scheme(url)) {
    snprintf(fixed, sizeof(fixed), "https://%s", url);
    target = fixed;
  }

  int rc = navigate_ctx(ctxs[n], target, want_wait ? "interactive" : "none",
                       want_wait ? 60 : 10);
  if (rc == EXIT_OK)
    fprintf(stderr, "Job done, check ffsr tabs.\n");
  return rc;
}

/* ffsr search — PURE list of the accepted engines, by preference order.
 * No navigation (CLAUDE.md spec); the AI composes URLs with go. */
static int cmd_search_list(void) {
  printf("google https://www.google.com/search?q=\n");
  printf("paulgo https://paulgo.io/search?q=\n");
  printf("startpage https://www.startpage.com/sp/search?query=\n");
  printf("duckduckgo https://html.duckduckgo.com/html/?q=\n");
  return EXIT_OK;
}

/* ffsr search go <tabs> <query> — search IN PARALLEL (burst of
 * wait:none navigations), one engine per tab, POSITIONAL mapping:
 * position 1=google, 2=paulgo, 3=startpage, 4=duckduckgo. Tabs are
 * comma-separated; an EMPTY position (double comma) skips the engine.
 * The query is ALWAYS the last argument. Silent on success. */
static int cmd_search_go(const char *tabs_list, const char *query) {
  static const char *bases[4] = {
    "https://www.google.com/search?q=",
    "https://paulgo.io/search?q=",
    "https://www.startpage.com/sp/search?query=",
    "https://html.duckduckgo.com/html/?q="
  };
  char enc[4096];
  url_encode(query, enc, sizeof(enc));

  char cw[64];
  char ctxs[64][64];
  char urls[64][2048];
  int count = resolve_dedicated(cw, ctxs, urls);
  if (count == 0) {
    log_err("dedicated window not found — no tabs?");
    return EXIT_ERR;
  }

  int pos = 0, err = 0;
  const char *p = tabs_list;
  while (*p && pos < 4) {
    const char *comma = strchr(p, ',');
    int len = comma ? (int)(comma - p) : (int)strlen(p);
    if (len == 0) {            /* empty position: engine skipped */
      pos++;
      p = comma ? comma + 1 : p + 1;
      continue;
    }
    char buf[8];
    if (len > 7) len = 7;
    memcpy(buf, p, (size_t)len);
    buf[len] = '\0';
    char *end = NULL;
    long n = strtol(buf, &end, 10);
    if (!end || *end != '\0' || n < 0 || n > 9) {
      log_err("invalid tab '%s' (expected 0-9)", buf);
      return EXIT_BADARGS;
    }
    if (n >= count) {
      log_err("tab %ld out of range: dedicated window has %d tab(s)",
              n, count);
      return EXIT_BADARGS;
    }
    char full[4600];
    snprintf(full, sizeof(full), "%s%s", bases[pos], enc);
    if (navigate_ctx(ctxs[n], full, "none", 10) != EXIT_OK) err = 1;
    pos++;
    p = comma ? comma + 1 : p + len;
  }
  if (pos == 0) {
    log_err("no tab given");
    return EXIT_BADARGS;
  }
  if (*p) {
    log_err("too many positions: 4 engines max");
    return EXIT_BADARGS;
  }
  if (err) {
    log_err("some navigations failed");
    return EXIT_ERR;
  }
  fprintf(stderr, "Job done, check ffsr tabs.\n");
  return EXIT_OK;
}

/* ffsr f5 <N> w — HARD reload ALWAYS (cache:bypass, Ctrl+Shift+R
 * equivalent, cache never preserved — CLAUDE.md spec). The 'w' tunes
 * the wait: without 'w' → immediate response; with 'w' → wait for full
 * load. Silent on success. */
static int cmd_f5(int n, int want_wait) {
  char cw[64];
  char ctxs[64][64];
  char urls[64][2048];
  int count = resolve_dedicated(cw, ctxs, urls);
  if (count == 0) {
    log_err("dedicated window not found — no tabs?");
    return EXIT_ERR;
  }
  if (n >= count) {
    log_err("tab %d out of range: dedicated window has %d tab(s)", n, count);
    return EXIT_BADARGS;
  }

  char trame[512];
  snprintf(trame, sizeof(trame),
           "{\"id\":3,\"method\":\"browsingContext.reload\",\"params\":{"
           "\"context\":\"%.63s\",\"cache\":\"bypass\",\"wait\":\"%s\"}}",
           ctxs[n], want_wait ? "complete" : "none");

  Buf out;
  buf_init(&out);
  if (cli_call_t(trame, &out, want_wait ? 60 : 10) != EXIT_OK) {
    buf_free(&out);
    return EXIT_ERR;
  }
  int err = strstr(out.data, "\"type\":\"error\"") != NULL;
  if (err) log_err("reload: %.*s", (int)(out.len < 400 ? out.len : 400),
                   out.data);
  buf_free(&out);
  return err ? EXIT_ERR : EXIT_OK;
}

/* Collects the direct iframe contextIds of the `top` tab: the getTree response nests children in the parent object's "children" field (there is no "parent" child field — observation 2026-08-12). Returns the count found.
 * the getTree response nests the children in the "children" field of
 * the parent object (there is no "parent" child field —
 * observation 2026-08-12). Returns the count found. */
static int collect_children(const char *doc, size_t len, const char *top,
                            char ids[][64], int max) {
  size_t rs = 0, re = 0, cs = 0, ce = 0;
  if (json_value_bounds(doc, len, "result", &rs, &re) != 1) return 0;
  if (json_value_bounds(doc + rs, re - rs, "contexts", &cs, &ce) != 1) return 0;
  const char *arr = doc + rs + cs;
  size_t pos = 1, s = 0, e = 0;
  while (json_array_next(arr, ce - cs, &pos, &s, &e) > 0) {
    size_t vs = 0, ve = 0;
    if (json_get_str_bounds(arr + s, e - s, "context", &vs, &ve) != JSON_STR)
      continue;
    size_t tl = ve - vs;
    if (tl != strlen(top) || memcmp(arr + s + vs, top, tl) != 0) continue;
    /* the found tab: list its children (the children array) */
    size_t chs = 0, che = 0;
    if (json_value_bounds(arr + s, e - s, "children", &chs, &che) != 1)
      return 0;
    const char *ch = arr + s + chs;
    if (ch[0] != '[') return 0;
    size_t p2 = 1, s2 = 0, e2 = 0;
    int k = 0;
    while (k < max && json_array_next(ch, che - chs, &p2, &s2, &e2) > 0) {
      size_t cvs = 0, cve = 0;
      if (json_get_str_bounds(ch + s2, e2 - s2, "context", &cvs, &cve)
          != JSON_STR) continue;
      size_t l = cve - cvs < 63 ? cve - cvs : 63;
      memcpy(ids[k], ch + s2 + cvs, l);
      ids[k][l] = '\0';
      k++;
    }
    return k;
  }
  return 0;
}

/* The foundation of tab extraction: a script.evaluate on the context,
 * the (JSON string) value unescaped in out → actual raw content. */
static int evaluate_ctx_t(const char *ctx, const char *expression, Buf *out,
                          int timeout_s) {
  char trame[6000];
  snprintf(trame, sizeof(trame),
           "{\"id\":3,\"method\":\"script.evaluate\",\"params\":{"
           "\"expression\":\"%s\","
           "\"target\":{\"context\":\"%.63s\"},"
           "\"awaitPromise\":false,\"resultOwnership\":\"none\"}}",
           expression, ctx);
   Buf raw;
   if (cli_call_t(trame, &raw, timeout_s) != EXIT_OK) return -1;
   size_t vs = 0, ve = 0;
  if (get_script_value(raw.data, raw.len, &vs, &ve) != 0) {
    log_err("script.evaluate: unexpected response");
    buf_free(&raw);
    return -1;
  }
  buf_reset(out);
  if (json_unescape(out, raw.data + vs, ve - vs) != 0) {
    buf_free(&raw);
    return -1;
  }
  buf_free(&raw);
  return 0;
}

static int evaluate_ctx(const char *ctx, const char *expression, Buf *out) {
  /* 120 s : the bridge can mark a pause of ~30 s in the middle
 * a large serialization (observation 2026-08-12, google 3.2 MB) */
  return evaluate_ctx_t(ctx, expression, out, 120);
}

/* ffsr get child <N> — the HTML of the iframes of the tab : getTree...
 * maxDepth:1 (the direct children only — the multi-Mo complete tree
 * exceeds the tunnel fragmentation management, observation 2026-08-12)
 * → the contexts whose parent is the tab → their outerHTML,
 * separated by context lines. Raw output. */
static int get_child(const char *top_ctx) {
  Buf out;
  if (cli_call("{\"id\":2,\"method\":\"browsingContext.getTree\","
               "\"params\":{\"maxDepth\":1}}", &out) != EXIT_OK)
    return EXIT_ERR;
  char ids[64][64];
  int n = collect_children(out.data, out.len, top_ctx, ids, 64);
  buf_free(&out);

  int printed = 0;
  for (int i = 0; i < n; i++) {
    printf("===== %s =====\n", ids[i]);
    Buf h;
    buf_init(&h);
    if (evaluate_ctx(ids[i], "document.documentElement.outerHTML", &h) == 0) {
      if (h.len > 0) fwrite(h.data, 1, h.len, stdout);
      fputc('\n', stdout);
      buf_free(&h);
      printed++;
    }
  }
  if (printed == 0) printf("(no child contexts in tab)\n");
  return EXIT_OK;
}

/* ------------------------------------------------ get-file channel */

/* Sends a full BiDi evaluation frame WITHOUT writing the response to stdout
 * the bridge's response may take ~10 s to arrive; we wait for it (cli_call) but then discard it — the staging file is the only proof
 *
 * (send_trame is not suitable: it prints the response.) */
static int send_eval_no_wait(const char *ctx, const char *expr) {
  Buf j;
  buf_init(&j);
  buf_puts(&j, "{\"id\":3,\"method\":\"script.evaluate\",\"params\":{\"expression\":\"");
  json_escape(&j, expr, strlen(expr));
  buf_puts(&j, "\",\"target\":{\"context\":\"");
  json_escape(&j, ctx, strlen(ctx));
  buf_puts(&j, "\"},\"awaitPromise\":false,\"resultOwnership\":\"none\"}}");
  Buf out;
  buf_init(&out);
  int rc = cli_call(j.data ? j.data : "", &out);
  buf_free(&out);
  buf_free(&j);
  return rc == EXIT_OK ? 0 : -1;
}

/* Blob download of the rendered (outerHTML): Firefox writes the binary file to the staging,
 * Binary file in the staging, WITHOUT BiDi serialization (the bottleneck).
 * We await NO response: the file appearing in the staging is the only proof.
 *  */
static int blob_download(const char *ctx, int n) {
  char expr[2200];
  snprintf(expr, sizeof(expr),
           "(()=>{const s=document.documentElement.outerHTML;"
           "const b=new Blob([s],{type:'text/html'});"
           "const a=document.createElement('a');a.href=URL.createObjectURL(b);"
           "a.download='ffsr_get%d.html';"
           "document.body.appendChild(a);a.click();return s.length})()", n);
  return send_eval_no_wait(ctx, expr);
}

/* Source (URL of the tab) download — mp4, images, raw HTML.
 * Same principle: no response wait. */
static int src_download(const char *ctx, int n, const char *url) {
  Buf jurl;
  buf_init(&jurl);
  buf_puts(&jurl, "\"");
  if (json_escape(&jurl, url, strlen(url)) != 0 || buf_puts(&jurl, "\"") != 0) {
    buf_free(&jurl);
    return -1;
  }
  char expr[4600];
  snprintf(expr, sizeof(expr),
           "(()=>{const a=document.createElement('a');a.href=%s;"
           "a.download='ffsr_src%d';"
           "document.body.appendChild(a);a.click();return 'ok'})()",
           jurl.data ? jurl.data : "\"\"", n);
  buf_free(&jurl);
  return send_eval_no_wait(ctx, expr);
}

/* Source download via JS (option A, 2026-08-14): navigate the tab to
 * about:blank FIRST (a clean context where fetch works — Firefox's native
 * JSON viewer has an opaque origin and fetch fails there with
 * NetworkError, observed 2026-08-14), then fetch the CAPTURED url as a
 * blob and trigger the download. The top-level browsingContext id is
 * preserved across navigation (BiDi), so the same ctx is reused. CORS
 * caveat: the fetch is cross-origin from about:blank → the target must
 * send `access-control-allow-origin: *` (models.dev does; validated). */
static int src_download_js(const char *ctx, int n, const char *url) {
  /* Step 1: empty the tab into about:blank to escape the JSON viewer.
   * A REAL browsingContext.navigate is mandatory: window.location.href
   * from the JSON viewer keeps an opaque-origin realm where fetch keeps
   * failing with NetworkError (observed 2026-08-14). */
  Buf nav;
  char navt[256];
  snprintf(navt, sizeof(navt),
           "{\"id\":3,\"method\":\"browsingContext.navigate\",\"params\":{"
           "\"context\":\"%.63s\",\"url\":\"about:blank\",\"wait\":\"none\"}}",
           ctx);
  buf_init(&nav);
  if (cli_call(navt, &nav) != EXIT_OK) {
    buf_free(&nav);
    return -1;
  }
  buf_free(&nav);
  sleep(10);   /* let the navigation settle */

  /* Step 2: fetch the captured url from the now-blank context. */
  Buf jurl;
  buf_init(&jurl);
  buf_puts(&jurl, "\"");
  if (json_escape(&jurl, url, strlen(url)) != 0 || buf_puts(&jurl, "\"") != 0) {
    buf_free(&jurl);
    return -1;
  }
  char expr[1600];
  snprintf(expr, sizeof(expr),
           "(()=>{"
           "const name='ffsr_src%d';"
           "return fetch(%s).then(r=>{"
           "  if(!r.ok) throw new Error('HTTP '+r.status);"
           "  return r.blob();"
           "}).then(b=>{"
           "  const a=document.createElement('a');"
           "  a.href=URL.createObjectURL(b);"
           "  a.download=name;"
           "  (document.body||document.documentElement).appendChild(a);"
           "  a.click();"
           "  setTimeout(()=>URL.revokeObjectURL(a.href),5000);"
           "  return 'ok';"
           "}).catch(e=>{console.error('ffsr_src',e); throw e;});"
           "})()", n, jurl.data ? jurl.data : "\"\"");
  buf_free(&jurl);
  return send_eval_no_wait(ctx, expr);
}

/* Looks for a staging file (exact name, or prefix if src=1 since MIME type is chosen by Firefox)
 * the MIME type is chosen by Firefox). If present AND stable (2
 * identical stats at 1 s: write complete) : lit, purge, 0. */
static int read_staging(const char *name, int src, Buf *out) {
  DIR *dir = opendir(STAGING_DIR);
  if (!dir) return -1;
  char found[512] = "";
  size_t nlen = strlen(name);
  struct dirent *e;
  while ((e = readdir(dir)) != NULL) {
    if (src) {
      if (strncmp(e->d_name, name, nlen) == 0 &&
          (e->d_name[nlen] == '.' || e->d_name[nlen] == '\0')) {
        snprintf(found, sizeof(found), "%s/%s", STAGING_DIR, e->d_name);
        break;
      }
    } else if (strcmp(e->d_name, name) == 0) {
      snprintf(found, sizeof(found), "%s/%s", STAGING_DIR, e->d_name);
      break;
    }
  }
  closedir(dir);
  if (found[0] == '\0') return -1;

  struct stat a, b;
  if (stat(found, &a) != 0 || a.st_size <= 0) return -1;
  sleep(1);
  if (stat(found, &b) != 0 || b.st_size != a.st_size) return -1;

  FILE *f = fopen(found, "rb");
  if (!f) return -1;
  buf_reset(out);
  char buf[65536];
  size_t r;
  while ((r = fread(buf, 1, sizeof(buf), f)) > 0) buf_append(out, buf, r);
  fclose(f);
  remove(found);
  return 0;
}

/* Staging poll: 1×/s, global timeout — the bridge takes 10-120 s to release
 * free an abandoned serialization before the click leaves. */
static int wait_staging(const char *name, int src, Buf *out) {
  for (int i = 0; i < FALLBACK_TO; i++) {
    if (read_staging(name, src, out) == 0) return 0;
    sleep(1);
  }
  return -1;
}

/* ffsr get file <N> w [src]: binary channel. Without w: click + immediate return,
 * LLM polls to read the file once written
 * With w: click + poll 1×/s → stdout. */
static int cmd_get_file(int n, int want_wait, int src, int js) {
  char cw[64];
  char ctxs[64][64];
  char urls[64][2048];
  int count = resolve_dedicated(cw, ctxs, urls);
  if (count == 0) {
    log_err("dedicated window not found — no tabs?");
    return EXIT_ERR;
  }
  if (n >= count) {
    log_err("tab %d out of range: dedicated window has %d tab(s)", n, count);
    return EXIT_BADARGS;
  }

  char name[64];
  snprintf(name, sizeof(name), src ? "ffsr_src%d" : "ffsr_get%d.html", n);

  Buf out;
  buf_init(&out);
  if (read_staging(name, src, &out) == 0) {
    /* EXACT binary: no trailing \\n (sha must match) */
    if (out.len > 0) fwrite(out.data, 1, out.len, stdout);
    buf_free(&out);
    return EXIT_OK;
  }
  buf_free(&out);

  int rc = src ? (js ? src_download_js(ctxs[n], n, urls[n])
                     : src_download(ctxs[n], n, urls[n]))
              : blob_download(ctxs[n], n);
  if (rc != 0) {
    log_err("get file: download click failed (bridge busy?) — retry");
    return EXIT_ERR;
  }
  if (!want_wait) {
    printf("(download launched — retry `ffsr get file %d%s` in ~5 s)\n", n,
           src ? " src" : "");
    return EXIT_OK;
  }

  buf_init(&out);
  if (wait_staging(name, src, &out) != 0) {
    log_err("get file: no file within %ds", FALLBACK_TO);
    buf_free(&out);
    return EXIT_ERR;
  }
  if (out.len > 0) fwrite(out.data, 1, out.len, stdout);
  buf_free(&out);
  return EXIT_OK;
}

/* ------------------------------------------------------- screen */

/* Decodes standard base64 (A-Za-z0-9+/=) into out. 0 or -1. */
static int base64_decode(const char *s, size_t n, Buf *out) {
  int val = 0, bits = 0;
  for (size_t i = 0; i < n; i++) {
    int d;
    char c = s[i];
    if (c >= 'A' && c <= 'Z') d = c - 'A';
    else if (c >= 'a' && c <= 'z') d = c - 'a' + 26;
    else if (c >= '0' && c <= '9') d = c - '0' + 52;
    else if (c == '+') d = 62;
    else if (c == '/') d = 63;
    else if (c == '=') break;
    else continue;
    val = (val << 6) | d;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      char b = (char)((val >> bits) & 0xFF);
      if (buf_append(out, &b, 1) != 0) return -1;
    }
  }
  return 0;
}

/* ffsr screen <N> — capture WebP of the tab N viewport, served EXACT
 * on stdout (no directory: redirection shell, same philosophy as get file)
 * get file). The capture requires a VISIBLE page — the bridge waits indefinitely
 * indefinitely otherwise discovered 2026-08-12: browsingContext.activate
 * first, then captureScreenshot (webp 0.8, response in ~0.1 s).*/
static int cmd_screen(int n) {
  char cw[64];
  char ctxs[64][64];
  char urls[64][2048];
  int count = resolve_dedicated(cw, ctxs, urls);
  if (count == 0) {
    log_err("dedicated window not found — no tabs?");
    return EXIT_ERR;
  }
  if (n >= count) {
    log_err("tab %d out of range: dedicated window has %d tab(s)", n, count);
    return EXIT_BADARGS;
  }
  Buf out;
  buf_init(&out);
  char trame[700];
  /* Step 1: activate — brings the browsing context to the foreground so
   * the bridge knows it's visible (captureScreenshot waits indefinitely
   * otherwise — confirmed 2026-08-12). */
  snprintf(trame, sizeof(trame),
           "{\"id\":8,\"method\":\"browsingContext.activate\","
           "\"params\":{\"context\":\"%.63s\"}}", ctxs[n]);
  if (cli_call(trame, &out) != EXIT_OK) {
    log_err("screen: activate failed");
    buf_free(&out);
    return EXIT_ERR;
  }
  buf_reset(&out);
  /* Step 2: scroll to top + stop ongoing loads. Heavy search-result pages
   * keep Firefox busy rendering (lazy images, video, XHR) → the animation
   * frame callback that captureScreenshot waits for never fires within
   * the 10 s deadline. Scrolling to (0,0) ensures already-rendered content
   * is in the viewport; window.stop() kills dangling requests. Both are
   * no-ops if the page is already idle/complete. */
  if (evaluate_ctx(ctxs[n], "window.scrollTo(0,0);window.stop();'ok'", &out) != 0) {
    log_msg("screen: scroll/stop returned non-string (non-fatal)");
  }
  buf_reset(&out);
  /* Step 3: captureScreenshot (webp 0.8) — 10 s deadline per spec. */
  snprintf(trame, sizeof(trame),
           "{\"id\":9,\"method\":\"browsingContext.captureScreenshot\","
           "\"params\":{\"context\":\"%.63s\",\"format\":{"
           "\"type\":\"image/webp\",\"quality\":0.8}}}", ctxs[n]);
  if (cli_call(trame, &out) != EXIT_OK) {
    buf_free(&out);
    return EXIT_ERR;
  }
  /* Extract "result" first, then find "data" inside it — the
   * captureScreenshot response nests data inside result:
   * {"type":"success","id":9,"result":{"data":"<b64>"}}
   * (json_get_str_bounds only scans top-level keys.) */
  size_t rs = 0, re = 0;
  if (json_value_bounds(out.data, out.len, "result", &rs, &re) != 1) {
    log_err("screen: no \"result\" in capture response");
    buf_free(&out);
    return EXIT_ERR;
  }
  size_t start, end;
  if (json_get_str_bounds(out.data + rs, re - rs, "data", &start, &end) != JSON_STR) {
    log_err("screen: no \"data\" field in capture response");
    buf_free(&out);
    return EXIT_ERR;
  }
  Buf img;
  buf_init(&img);
  if (base64_decode(out.data + rs + start, end - start, &img) != 0 || img.len == 0) {
    log_err("screen: base64 decode failed");
    buf_free(&out);
    buf_free(&img);
    return EXIT_ERR;
  }
  if (img.len > 0) fwrite(img.data, 1, img.len, stdout);
  buf_free(&out);
  buf_free(&img);
  return EXIT_OK;
}

/* ------------------------------------------------------- get con */

/* JSON mini-parser: separates frames from the stream (string-aware:
 * braces inside strings do not count). Prints
 * each log.entryAdded on stdout. Returns at EOF (daemon closed).*/
static void stream_loop(int fd) {
  char tmp[16384];
  Buf acc;
  buf_init(&acc);
  int depth = 0;
  int in_str = 0, esc = 0;
  for (;;) {
    ssize_t n = read(fd, tmp, sizeof(tmp));
    if (n <= 0) return;
    for (ssize_t i = 0; i < n; i++) {
      char ch = tmp[i];
      buf_append(&acc, &ch, 1);
      if (in_str) {
        if (esc) esc = 0;
        else if (ch == '\\') esc = 1;
        else if (ch == '"') in_str = 0;
        continue;
      }
      if (ch == '"') { in_str = 1; continue; }
      if (ch == '{') depth++;
      else if (ch == '}') {
        depth--;
        if (depth == 0) {
          if (strstr(acc.data, "\"method\":\"log.entryAdded\"")) {
            fwrite(acc.data, 1, acc.len, stdout);
            fputc('\n', stdout);
            fflush(stdout);
          }
          buf_reset(&acc);
        }
      }
    }
  }
}

/* ffsr get con <N> — Console stream (only stream in v1): subscribes to
 * log.entryAdded on tab N's context (session.subscribe, the
 * connection stays open on daemon side) and prints each entry as they come
 * on stdout. Stops at Ctrl+C (SIGINT kills the process,
 * daemon releases the slot).*/
static int cmd_get_con(int n) {
  char cw[64];
  char ctxs[64][64];
  char urls[64][2048];
  int count = resolve_dedicated(cw, ctxs, urls);
  if (count == 0) {
    log_err("dedicated window not found — no tabs?");
    return EXIT_ERR;
  }
  if (n >= count) {
    log_err("tab %d out of range: dedicated window has %d tab(s)", n, count);
    return EXIT_BADARGS;
  }
  int fd = tunnel_connect();
  if (fd < 0) {
    log_err("ffsrd unreachable (%s) — is it running? (ffsr d status)",
            strerror(errno));
    return EXIT_ERR;
  }
  char trame[2048];
  snprintf(trame, sizeof(trame),
           "{\"id\":7,\"method\":\"session.subscribe\",\"params\":{"
           "\"events\":[\"log.entryAdded\"],\"contexts\":[\"%.63s\"]}}",
           ctxs[n]);
  if (write_all(fd, trame, strlen(trame)) != 0) {
    log_err("tunnel write: %s", strerror(errno));
    close(fd);
    return EXIT_ERR;
  }
  fprintf(stderr, "(get con %d: streaming console — Ctrl+C to stop)\n", n);
  stream_loop(fd);
  close(fd);
  return EXIT_OK;
}

/* ffsr get [html|txt|net|child|file|con] <N> [src] w— Grouped core of extractions
 * extractions (HTML, visible text, network snapshot = same mechanism,
 * only the expression changes; child = iframe loop;
 * file = binary blob/source stream; con = console stream). RAW output,
 BRUTE. */
static int cmd_get(const char *type, int n, int want_wait) {
  char cw[64];
  char ctxs[64][64];
  char urls[64][2048];
  int count = resolve_dedicated(cw, ctxs, urls);
  if (count == 0) {
    log_err("dedicated window not found — no tabs?");
    return EXIT_ERR;
  }
  if (n >= count) {
    log_err("tab %d out of range: dedicated window has %d tab(s)", n, count);
    return EXIT_BADARGS;
  }

  if (strcmp(type, "child") == 0) return get_child(ctxs[n]);
  if (strcmp(type, "file") == 0) return cmd_get_file(n, want_wait, 0, 0);

  const char *expr = NULL;
  if (strcmp(type, "html") == 0)
    expr = "document.documentElement.outerHTML";
  else if (strcmp(type, "txt") == 0)
    expr = "document.body.innerText";
  else if (strcmp(type, "net") == 0)
    expr = "JSON.stringify(performance.getEntriesByType('resource'))";
  else
    return EXIT_BADARGS;

  Buf out;
  buf_init(&out);
  /* Direct attempt: serialized by the bridge. Short timeout — if the
   * serializer overflows (heavy pages, busy bridge), the fallback blob
   * takes over (same content: the rendering), via disk with no limit. */
  if (evaluate_ctx_t(ctxs[n], expr, &out, SERIALIZE_TO) != 0) {
    buf_free(&out);
    if (strcmp(type, "html") != 0) {
      log_err("get %s: serialization failed", type);
      return EXIT_ERR;
    }
    log_err("serialization failed — falling back to the binary channel");
    Buf fb;
    buf_init(&fb);
    char name[64];
    snprintf(name, sizeof(name), "ffsr_get%d.html", n);
    if (blob_download(ctxs[n], n) == 0 && wait_staging(name, 0, &fb) == 0) {
      if (fb.len > 0) fwrite(fb.data, 1, fb.len, stdout);
      fputc('\n', stdout);
      buf_free(&fb);
      return EXIT_OK;
    }
    buf_free(&fb);
    log_err("fallback failed (bridge busy?) — retry");
    return EXIT_ERR;
  }
  if (out.len > 0) fwrite(out.data, 1, out.len, stdout);
  fputc('\n', stdout);
  buf_free(&out);
  return EXIT_OK;
}

static int show_usage(void) {
    printf("ffsr — FireFox Simple Relay\n"
           "\n"
           "CONTEXT\n"
           "  Controls a dedicated Firefox window with 10 fixed tabs numbered 0–9.\n"
           "  In all commands, <N> means a tab index (0 to 9).\n"
           "  The daemon (ffsrd) must be running (see: ffsr d status).\n"
           "\n"
           "REFERENCE\n"
           "  (no args) / help              Show this help\n"
           "  tabs                          List the 10 tabs (index, URL, title, size)\n"
           "  search                        List available search engines and their base URLs\n"
           "\n"
           "NAVIGATION\n"
           "  go <N> <url> w                Navigate tab N  (w = wait until interactive)\n"
           "  f5 <N> w                      Hard reload tab N (bypass cache)\n"
           "  search go <N,N,N,N> <query>   Parallel search (up to 4 engines)\n"
           "                                Positions:\n"
           "                                  1 = Google\n"
           "                                  2 = Paulgo\n"
           "                                  3 = Startpage\n"
           "                                  4 = DuckDuckGo\n"
           "                                Use empty slots to skip an engine.\n"
           "                                Example:\n"
           "                                  ffsr search go 0,2,,4 \"firefox bidi\"\n"
           "                                  Google on tab 0, Startpage on tab 2,\n"
           "                                  DuckDuckGo on tab 4 (Paulgo skipped)\n"
           "\n"
           "RETRIEVAL\n"
           "  get <N>                         Full HTML of tab N (outerHTML, binary fallback)\n"
           "  get txt <N>                     Visible text only (innerText)\n"
           "  get file <N> w                  Rendered DOM via binary channel (large pages)\n"
           "  get file <N> src w              Raw source via browser download (uses session)\n"
           "  get file <N> src js w           Raw source via JS fetch from an about:blank tab\n"
           "                                  Works for public CORS-friendly URLs (ACAO: *)\n"
           "                                  Does NOT use the target tab's cookies/session\n"
           "                                  (prefer `src` for authenticated content)\n"
           "  get child <N>                   HTML of iframes / child contexts\n"
           "  get net <N>                     Network resource snapshot\n"
           "  get con <N>                     Live console stream (Ctrl+C to stop)\n"
           "\n"
           "SYSTEM\n"
           "  d status|start|stop|restart     Control the ffsrd daemon\n"
           "  bidi <json-bidi-frame>          Raw BiDi frame pass-through\n"
           "\n"
           "TYPICAL FLOW\n"
           "  1. ffsr tabs                  ← see what is currently in each tab\n"
           "  2. ffsr go 0 https://...      ← place a page where you need it\n"
           "  3. ffsr get txt 0             ← or get / get file depending on size");
  return EXIT_BADARGS;
}

int main(int argc, char **argv) {
  if (argc < 2) return show_usage();
  /* Special help flags: h, -h, help, -help, --help → show usage */
  if (argc == 2 &&
      (strcmp(argv[1], "h") == 0 ||
       strcmp(argv[1], "-h") == 0 ||
       strcmp(argv[1], "help") == 0 ||
       strcmp(argv[1], "-help") == 0 ||
       strcmp(argv[1], "--help") == 0)) {
    return show_usage();
  }
  /* Unknown command → show usage */
  if (argc == 2 &&
      strcmp(argv[1], "d") != 0 &&
      strcmp(argv[1], "tabs") != 0 &&
      strcmp(argv[1], "go") != 0 &&
      strcmp(argv[1], "search") != 0 &&
      strcmp(argv[1], "get") != 0 &&
      strcmp(argv[1], "screen") != 0 &&
      strcmp(argv[1], "f5") != 0 &&
      strcmp(argv[1], "bidi") != 0) {
    return show_usage();
  }

  /* ffsr bidi <frame> — raw BiDi passthrough */
  if (strcmp(argv[1], "bidi") == 0) {
    if (argc < 3) {
      log_err("usage: ffsr bidi <json-frame>");
      return EXIT_BADARGS;
    }
    Buf out;
    buf_init(&out);
    int rc = cli_call(argv[2], &out);
    if (rc == EXIT_OK && out.len > 0) {
      fwrite(out.data, 1, out.len, stdout);
      fputc('\n', stdout);
    }
    buf_free(&out);
    return rc;
  }
  if (strcmp(argv[1], "d") == 0) {
    if (argc < 3) {
      log_err("ffsr d requires a subcommand: status|start|stop|restart");
      return EXIT_BADARGS;
    }
    const char *sub = argv[2];
    const char *action = NULL;
    if      (strcmp(sub, "status")  == 0) action = "status";
    else if (strcmp(sub, "start")   == 0) action = "start";
    else if (strcmp(sub, "stop")    == 0) action = "stop";
    else if (strcmp(sub, "restart") == 0) action = "restart";
    else {
      log_err("ffsr d: unknown subcommand '%s'", sub);
      return EXIT_BADARGS;
    }

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "systemctl %s ffsrd.service", action);
    log_msg("$ %s", cmd);
    fflush(NULL);
    execlp("systemctl", "systemctl", action, "ffsrd.service", (char *)NULL);
    log_err("execlp systemctl: %s", strerror(errno));
    return EXIT_ERR;
  }

  /* ffsr tabs — the tab list */
  if (strcmp(argv[1], "tabs") == 0) return cmd_tabs();

  /* ffsr go <N> <url> w — navigate tab N of the dedicated window.
   * 'w' = wait:interactive (the prompt comes back once the DOM is
   * ready); without 'w' = wait:none (immediate response). */
  if (strcmp(argv[1], "go") == 0) {
    if (argc < 4 || argc > 5) {
      log_err("usage: ffsr go <N 0-9> <url> w");
      return EXIT_BADARGS;
    }
    char *end = NULL;
    long n = strtol(argv[2], &end, 10);
    if (!end || *end != '\0' || n < 0 || n > 9) {
      log_err("N must be an integer between 0 and 9");
      return EXIT_BADARGS;
    }
    int want_wait = (argc == 5 && strcmp(argv[4], "w") == 0);
    if (argc == 5 && !want_wait) {
      log_err("unknown 4th argument '%s' (expected: w)", argv[4]);
      return EXIT_BADARGS;
    }
    return cmd_go((int)n, argv[3], want_wait);
  }

  /* ffsr search | ffsr search go <tabs> <query> */
  if (strcmp(argv[1], "search") == 0) {
    if (argc == 2) return cmd_search_list();
    if (argc == 5 && strcmp(argv[2], "go") == 0)
      return cmd_search_go(argv[3], argv[4]);
    log_err("usage: ffsr search | ffsr search go <tabs 0-9,0-9> <query>");
    return EXIT_BADARGS;
  }

/* ffsr get [html|txt|net|child|file] <N> w [src]— Grouped core of extractions (HTML, visible text, network snapshot = same mechanism, only the expression changes; child = iframe loop; file = binary blob/source stream; con = console stream). RAW output. */
  if (strcmp(argv[1], "get") == 0) {
    if (argc < 3 || argc > 7) {
      log_err("usage: ffsr get [html|txt|net|child|file] <N 0-9> w [src] [js]");
      return EXIT_BADARGS;
    }
    const char *type = "html";
    const char *ns = argv[2];
    int want_wait = 0, src = 0, js = 0;
    if (argc == 4) {
      if (strcmp(argv[2], "w") == 0) {
        want_wait = 1;
        ns = argv[3];
      } else {
        type = argv[2];
        ns = argv[3];
      }
    } else {
      type = argv[2];
      ns = argv[3];
      for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "w") == 0) want_wait = 1;
        else if (strcmp(argv[i], "src") == 0) src = 1;
        else if (strcmp(argv[i], "js") == 0) js = 1;
        else {
          log_err("unknown argument '%s' (expected: w|src|js)", argv[i]);
          return EXIT_BADARGS;
        }
      }
    }
    if (strcmp(type, "html") != 0 && strcmp(type, "txt") != 0 &&
        strcmp(type, "net") != 0 && strcmp(type, "child") != 0 &&
        strcmp(type, "file") != 0 && strcmp(type, "con") != 0) {
      log_err("unknown get type '%s' (expected: html|txt|net|child|file|con)",
              type);
      return EXIT_BADARGS;
    }
    if (src && strcmp(type, "file") != 0) {
      log_err("src is only valid with `get file`");
      return EXIT_BADARGS;
    }
    char *end = NULL;
    long n = strtol(ns, &end, 10);
    if (!end || *end != '\0' || n < 0 || n > 9) {
      log_err("N must be an integer between 0 and 9");
      return EXIT_BADARGS;
    }
    if (strcmp(type, "file") == 0) return cmd_get_file((int)n, want_wait, src, js);
    if (strcmp(type, "con") == 0) return cmd_get_con((int)n);
    return cmd_get(type, (int)n, want_wait);
  }

  /* ffsr f5 <N> w — hard reload (cache bypass) of tab N */
  if (strcmp(argv[1], "screen") == 0) {
    if (argc != 3) {
      log_err("usage: ffsr screen <N 0-9>");
      return EXIT_BADARGS;
    }
    char *end = NULL;
    long n = strtol(argv[2], &end, 10);
    if (!end || *end != '\0' || n < 0 || n > 9) {
      log_err("N must be an integer between 0 and 9");
      return EXIT_BADARGS;
    }
    return cmd_screen((int)n);
  }

  if (strcmp(argv[1], "f5") == 0) {
    if (argc < 3 || argc > 4) {
      log_err("usage: ffsr f5 <N 0-9> w");
      return EXIT_BADARGS;
    }
    char *end = NULL;
    long n = strtol(argv[2], &end, 10);
    if (!end || *end != '\0' || n < 0 || n > 9) {
      log_err("N must be an integer between 0 and 9");
      return EXIT_BADARGS;
    }
    int want_wait = (argc == 4 && strcmp(argv[3], "w") == 0);
    if (argc == 4 && !want_wait) {
      log_err("unknown 3rd argument '%s' (expected: w)", argv[3]);
      return EXIT_BADARGS;
    }
    return cmd_f5((int)n, want_wait);
  }

  /* Otherwise: the BiDi frame is given as-is (JSON between quotes),
   * or assembled by the future commands (go/tabs/...). This first
   * version relays any raw argument. */
  const char *trame = argv[1];
  return send_trame(trame, strlen(trame));
}
