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

#define SOCK_PATH       "/run/ffsrd/ffsr.sock"
#define WINDOW_SOCK     "/run/ffsrd/window.sock"

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
  if (write(fd, trame, strlen(trame)) != (ssize_t)strlen(trame)) {
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
  if (read_until_eof(fd, &b, 5) != 0) {
    log_err("window.sock silent (timeout 5 s) — ffsrd busy?");
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

/* ffsr go <N> <url> [w] — navigate tab N of the dedicated window.
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

  return navigate_ctx(ctxs[n], target, want_wait ? "interactive" : "none",
                      want_wait ? 60 : 10);
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
  return err ? EXIT_ERR : EXIT_OK;
}

/* ffsr f5 <N> [w] — HARD reload ALWAYS (cache:bypass, Ctrl+Shift+R
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

static int show_usage(void) {
  printf("ffsr — FireFox Simple Relay (CLI)\n"
         "usage:\n"
         "  ffsr tabs                  | list the 10 tabs of the dedicated window\n"
         "  ffsr go <N 0-9> <url> [w]  | navigate tab N ('w' = wait for the load)\n"
         "  ffsr search                | list the accepted search engines\n"
         "  ffsr search go <tabs,> <query> | parallel search (position=1 google, 2 paulgo, 3 startpage, 4 ddg; empty position = skip)\n"
         "  ffsr f5 <N 0-9> [w]        | hard reload of tab N (cache bypass)\n"
         "  ffsr <json-bidi-frame>     | send the raw BiDi frame via the tunnel\n"
         "  ffsr d status              | service status (systemctl)\n"
         "  ffsr d start               | systemctl start ffsrd.service\n"
         "  ffsr d stop                | systemctl stop  ffsrd.service\n"
         "  ffsr d restart             | systemctl restart ffsrd.service\n");
  return EXIT_BADARGS;
}

int main(int argc, char **argv) {
  if (argc < 2) return show_usage();

  /* ffsr d … → systemctl (the only commands touching ffsrd) */
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

  /* ffsr go <N> <url> [w] — navigate tab N of the dedicated window.
   * 'w' = wait:interactive (the prompt comes back once the DOM is
   * ready); without 'w' = wait:none (immediate response). */
  if (strcmp(argv[1], "go") == 0) {
    if (argc < 4 || argc > 5) {
      log_err("usage: ffsr go <N 0-9> <url> [w]");
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

  /* ffsr f5 <N> [w] — hard reload (cache bypass) of tab N */
  if (strcmp(argv[1], "f5") == 0) {
    if (argc < 3 || argc > 4) {
      log_err("usage: ffsr f5 <N 0-9> [w]");
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